//go:build integration

package integration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/protocol"
)

func TestSettlementDisclosesReceiptOnlyAtBroadcast(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "success"
		if late {
			name = "insufficient-time"
		}
		t.Run(name, func(t *testing.T) {
			env := setup(t)
			tid, execution, _ := env.execute(t, 10, false)
			var broadcasts atomic.Int64
			ciphertext := hex.EncodeToString(execution.Receipt.Ciphertext)
			c := proxy(t, env, func(req rpcRequest) error {
				if req.Method == "eth_sendRawTransaction" {
					broadcasts.Add(1)
					return nil
				}
				for _, param := range req.Params {
					if strings.Contains(strings.ToLower(string(param)), ciphertext) {
						t.Errorf("receipt disclosed before broadcast via %s", req.Method)
						return errors.New("premature receipt disclosure")
					}
				}
				if req.Method == "eth_estimateGas" {
					t.Error("settlement performed remote gas estimation")
					return errors.New("unexpected estimation")
				}
				return nil
			}, nil)
			margin := uint64(30)
			if late {
				margin = 600 // The entire trade lasts 600 seconds.
			}
			_, err := c.Settle(env.ctx, env.owner, tid, execution.Receipt, margin)
			if late {
				if err == nil || broadcasts.Load() != 0 {
					t.Fatalf("late settlement: err=%v broadcasts=%d", err, broadcasts.Load())
				}
			} else if err != nil || broadcasts.Load() != 1 {
				t.Fatalf("settlement: err=%v broadcasts=%d", err, broadcasts.Load())
			}
		})
	}
}

// These synthetic receipts exercise the actual compiled TSC, including first
// credit of a new balance, ABI padding, zero/nonzero calldata and large outputs.
// They are gas-budget regression fixtures, not claims about enclave execution.
func TestSettlementLocalGasBudget(t *testing.T) {
	env := setup(t)
	for _, size := range []int{1, 31, 32, 33, 4096, 65536, 120*1024 - 320} {
		for _, fill := range []byte{0, 255} {
			tid, receipt := settlementFixture(t, env, bytes.Repeat([]byte{fill}, size))
			r, err := env.c.Settle(env.ctx, env.owner, tid, receipt, 30)
			if err != nil {
				t.Fatalf("size=%d fill=%d: %v", size, fill, err)
			}
			tx, _, err := env.c.RPC.TransactionByHash(env.ctx, r.TxHash)
			if err != nil {
				t.Fatal(err)
			}
			if r.GasUsed >= tx.Gas() {
				t.Fatalf("exhausted local gas budget: used=%d limit=%d", r.GasUsed, tx.Gas())
			}
			result, err := env.c.Result(env.ctx, tid)
			if err != nil || !bytes.Equal(result, receipt.Ciphertext) {
				t.Fatalf("result mismatch: %v", err)
			}
			t.Logf("ciphertext=%d fill=%d used=%d limit=%d", size, fill, r.GasUsed, tx.Gas())
		}
	}
}

func TestSettlementGasBudgetRejectsBeforeDisclosure(t *testing.T) {
	for _, reason := range []string{"oversized", "block-limit"} {
		t.Run(reason, func(t *testing.T) {
			env := setup(t)
			size := 128
			wantError := "block gas limit"
			if reason == "oversized" {
				// One more byte than the largest padded ABI call accepted above.
				size = 120*1024 - 319
				wantError = "120 KiB"
			}
			tid, receipt := settlementFixture(t, env, bytes.Repeat([]byte{0xf2}, size))
			c := proxy(t, env, func(req rpcRequest) error {
				if req.Method == "eth_sendRawTransaction" || req.Method == "eth_estimateGas" {
					t.Errorf("invalid gas budget reached %s", req.Method)
					return errors.New("unexpected receipt disclosure")
				}
				for _, param := range req.Params {
					if strings.Contains(strings.ToLower(string(param)), hex.EncodeToString(receipt.Ciphertext)) {
						t.Errorf("receipt disclosed via %s", req.Method)
					}
				}
				return nil
			}, func(req rpcRequest, body []byte) ([]byte, error) {
				if reason == "block-limit" && req.Method == "eth_getBlockByNumber" {
					var response map[string]json.RawMessage
					if err := json.Unmarshal(body, &response); err != nil {
						return nil, err
					}
					var header map[string]json.RawMessage
					if err := json.Unmarshal(response["result"], &header); err != nil {
						return nil, err
					}
					header["gasLimit"] = json.RawMessage(`"0x5208"`)
					response["result"], _ = json.Marshal(header)
					return json.Marshal(response)
				}
				return body, nil
			})
			if _, err := c.Settle(env.ctx, env.owner, tid, receipt, 30); err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("wanted %q rejection, got %v", wantError, err)
			}
		})
	}
}

func settlementFixture(t *testing.T, env *environment, ciphertext []byte) (uint64, protocol.Receipt) {
	t.Helper()
	c := env.c
	r, err := c.Send(env.ctx, env.owner, nil, "registerTrade", new(big.Int).SetUint64(env.did), [32]byte(protocol.H([]byte("gas fixture source"))), [32]byte(protocol.H([]byte("gas fixture measurement"))), ethcrypto.PubkeyToAddress(env.buyer.PublicKey), big.NewInt(1000000), uint64(600))
	if err != nil {
		t.Fatal(err)
	}
	tid, err := c.EventID(r, "TradeRegistered")
	if err != nil {
		t.Fatal(err)
	}
	id := new(big.Int).SetUint64(tid)
	if _, err = c.Send(env.ctx, env.buyer, big.NewInt(1000000), "deposit", id); err != nil {
		t.Fatal(err)
	}
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []bool{true, false} {
		k := env.owner
		if !account {
			k = env.buyer
		}
		if _, err = c.Send(env.ctx, k, nil, "confirmKey", id, ethcrypto.PubkeyToAddress(key.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
	receipt := protocol.Receipt{Commitment: env.app.Commitment, Ciphertext: ciphertext}
	receipt.Signature, err = protocol.Sign(key, protocol.ReceiptDigest(c.Domain(tid), receipt.Commitment, ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	return tid, receipt
}
