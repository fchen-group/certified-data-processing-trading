package experiment

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/holiman/uint256"
	"certified-data-processing-trading/pkg/chain"
)

func TestTradeGasChecks(t *testing.T) {
	t.Run("complete_bounded", func(t *testing.T) {
		var active, peak atomic.Int32
		var calls [24]atomic.Int32
		checks := make([]func(context.Context) error, len(calls))
		for i := range checks {
			checks[i] = func(context.Context) error {
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old; old = peak.Load() {
					if peak.CompareAndSwap(old, n) {
						break
					}
				}
				calls[i].Add(1)
				time.Sleep(time.Millisecond)
				return nil
			}
		}
		if err := runTradeGasChecks(context.Background(), checks, 4); err != nil {
			t.Fatal(err)
		}
		for i := range calls {
			if calls[i].Load() != 1 {
				t.Fatalf("check %d executed %d times", i, calls[i].Load())
			}
		}
		if peak.Load() > 4 {
			t.Fatalf("unbounded concurrency: %d", peak.Load())
		}
	})
	t.Run("failure", func(t *testing.T) {
		want := errors.New("semantic mismatch")
		checks := []func(context.Context) error{
			func(context.Context) error { return want },
			func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
		}
		if err := runTradeGasChecks(context.Background(), checks, 2); !errors.Is(err, want) {
			t.Fatal(err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := runTradeGasChecks(ctx, nil, 4); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

func TestTradeGasEstimatePinnedState(t *testing.T) {
	header := &types.Header{Number: big.NewInt(42), Difficulty: big.NewInt(0), GasLimit: 30_000_000, Time: 1000}
	block := tradeGasBlock{Number: 42, Hash: header.Hash()}
	for _, tc := range []struct {
		name          string
		errorText     string
		estimateCalls int
		headerCalls   int
	}{
		{"success", "", 1, 2},
		{"missing_block", "", 2, 2},
		{"missing_header_for_hash", "", 2, 2},
		{"contract_revert", "execution reverted: deposit not allowed", 1, 1},
		{"changed_before", "prerequisite block changed", 0, 1},
		{"changed_after", "prerequisite block changed", 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			estimates, headers := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     json.RawMessage   `json:"id"`
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				response := map[string]any{"jsonrpc": "2.0", "id": req.ID}
				switch req.Method {
				case "eth_getBlockByNumber":
					headers++
					if len(req.Params) != 2 || string(req.Params[0]) != `"0x2a"` {
						t.Errorf("unpinned header read: %s", req.Params)
					}
					copy := *header
					if tc.name == "changed_before" || tc.name == "changed_after" && headers == 2 {
						copy.Time++
					}
					response["result"] = &copy
				case "eth_estimateGas":
					estimates++
					var selector struct {
						BlockHash common.Hash `json:"blockHash"`
					}
					if len(req.Params) != 2 || json.Unmarshal(req.Params[1], &selector) != nil || selector.BlockHash != block.Hash {
						t.Errorf("estimate not pinned to verified hash: %s", req.Params)
					}
					if tc.name == "contract_revert" {
						response["error"] = map[string]any{"code": 3, "message": tc.errorText}
					} else if tc.name == "missing_block" && estimates == 1 {
						response["error"] = map[string]any{"code": -32000, "message": "header not found"}
					} else if tc.name == "missing_header_for_hash" && estimates == 1 {
						response["error"] = map[string]any{"code": -32000, "message": "header for hash not found"}
					} else {
						response["result"] = "0x186a0"
					}
				default:
					t.Errorf("unexpected RPC method: %s", req.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			node, err := ethclient.Dial(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer node.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			limit, err := tradeGasLimit(ctx, node, ethereum.CallMsg{}, block)
			if tc.errorText == "" {
				if err != nil || limit != 170000 {
					t.Fatalf("limit=%d error=%v", limit, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.errorText) {
				t.Fatalf("wanted %q, got %v", tc.errorText, err)
			}
			if estimates != tc.estimateCalls || headers != tc.headerCalls {
				t.Fatalf("RPC calls: estimates=%d headers=%d", estimates, headers)
			}
		})
	}
}

func TestTradeGasLogs(t *testing.T) {
	contract := common.HexToAddress("0x1234")
	run := &TradeGasRun{Plan: TradeGasPlan{PriceWei: "1000000000000"}, Owner: common.HexToAddress("0x1111"), Buyer: common.HexToAddress("0x2222"), ReceiptKey: common.HexToAddress("0x3333")}
	trial := &TradeGasTrial{TID: 7, Deadline: 12345, Ciphertext: []byte{1, 2, 3}}
	price, _ := new(big.Int).SetString(run.Plan.PriceWei, 10)
	for _, tc := range []struct {
		method, event string
		args          []any
		from, to      common.Address
	}{
		{"registerTrade", "TradeRegistered", nil, common.Address{}, common.Address{}},
		{"deposit", "Funded", []any{trial.Deadline}, run.Buyer, contract},
		{"confirmKey/DO", "", nil, common.Address{}, common.Address{}},
		{"confirmKey/DB", "KeyFixed", []any{run.ReceiptKey}, common.Address{}, common.Address{}},
		{"settle", "ResultDelivered", []any{[]byte(trial.Ciphertext)}, common.Address{}, common.Address{}},
		{"withdraw", "Withdrawn", []any{price}, contract, run.Owner},
		{"timeoutRefund", "Refunded", nil, contract, run.Buyer},
	} {
		t.Run(tc.method, func(t *testing.T) {
			var logs []*types.Log
			if tc.event != "" {
				event := chain.ABI.Events[tc.event]
				data, err := event.Inputs.NonIndexed().Pack(tc.args...)
				if err != nil {
					t.Fatal(err)
				}
				topic := common.BigToHash(big.NewInt(7))
				if tc.method == "withdraw" {
					topic = common.BytesToHash(run.Owner.Bytes())
				}
				logs = []*types.Log{{Address: contract, Topics: []common.Hash{event.ID, topic}, Data: data}}
			}
			if err := checkTradeLogs(contract, run, trial, tc.method, logs); err != nil {
				t.Fatalf("legacy logs: %v", err)
			}
			if tc.from != (common.Address{}) {
				system := types.EthTransferLog(tc.from, tc.to, uint256.MustFromBig(price))
				for _, enriched := range [][]*types.Log{append([]*types.Log{system}, logs...), append(append([]*types.Log{}, logs...), system)} {
					if err := checkTradeLogs(contract, run, trial, tc.method, enriched); err != nil {
						t.Fatalf("system transfer plus TSC event: %v", err)
					}
				}
				badTransfer := types.EthTransferLog(tc.to, tc.from, uint256.MustFromBig(price))
				badAmount := types.EthTransferLog(tc.from, tc.to, uint256.NewInt(1))
				for _, bad := range [][]*types.Log{append([]*types.Log{system, system}, logs...), append([]*types.Log{badTransfer}, logs...), append([]*types.Log{badAmount}, logs...)} {
					if err := checkTradeLogs(contract, run, trial, tc.method, bad); err == nil {
						t.Fatal("accepted duplicated or incorrect system transfer")
					}
				}
			} else if err := checkTradeLogs(contract, run, trial, tc.method, append([]*types.Log{types.EthTransferLog(run.Buyer, contract, uint256.MustFromBig(price))}, logs...)); err == nil {
				t.Fatal("accepted transfer on a non-transfer operation")
			}
			for _, extra := range []*types.Log{nil, {Address: common.HexToAddress("0x9876")}, {Address: contract, Removed: true}} {
				if err := checkTradeLogs(contract, run, trial, tc.method, append(append([]*types.Log{}, logs...), extra)); err == nil {
					t.Fatal("accepted foreign, missing or removed log")
				}
			}
			if len(logs) != 0 {
				if err := checkTradeLogs(contract, run, trial, tc.method, nil); err == nil {
					t.Fatal("accepted missing TSC event")
				}
				if err := checkTradeLogs(contract, run, trial, tc.method, append(logs, logs[0])); err == nil {
					t.Fatal("accepted duplicate TSC event")
				}
				wrong := *logs[0]
				wrong.Topics = append([]common.Hash{}, logs[0].Topics...)
				wrong.Topics[1] = common.Hash{}
				if err := checkTradeLogs(contract, run, trial, tc.method, []*types.Log{&wrong}); err == nil {
					t.Fatal("accepted incorrect event identity")
				}
				wrong = *logs[0]
				wrong.Data = append(append([]byte{}, wrong.Data...), 0)
				if err := checkTradeLogs(contract, run, trial, tc.method, []*types.Log{&wrong}); err == nil {
					t.Fatal("accepted incorrect event payload")
				}
			}
		})
	}
}
