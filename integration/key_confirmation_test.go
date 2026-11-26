//go:build integration

package integration

import (
	"encoding/json"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/protocol"
)

// The estimate is genuine, but another participant confirms before broadcast.
// This reproduces the state-dependent gas increase observed on Sepolia.
func TestKeyConfirmationSurvivesConcurrentConfirmation(t *testing.T) {
	for _, ownerSecond := range []bool{true, false} {
		name := "buyer-second"
		if ownerSecond {
			name = "owner-second"
		}
		t.Run(name, func(t *testing.T) {
			env := setup(t)
			r, err := env.c.Send(env.ctx, env.owner, nil, "registerTrade", new(big.Int).SetUint64(env.did), [32]byte(protocol.H([]byte("source"))), [32]byte(protocol.H([]byte("measurement"))), ethcrypto.PubkeyToAddress(env.buyer.PublicKey), big.NewInt(1000000), uint64(600))
			if err != nil {
				t.Fatal(err)
			}
			tid, err := env.c.EventID(r, "TradeRegistered")
			if err != nil {
				t.Fatal(err)
			}
			id := new(big.Int).SetUint64(tid)
			if _, err := env.c.Send(env.ctx, env.buyer, big.NewInt(1000000), "deposit", id); err != nil {
				t.Fatal(err)
			}
			key, err := ethcrypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			address := ethcrypto.PubkeyToAddress(key.PublicKey)
			first, second := env.owner, env.buyer
			if ownerSecond {
				first, second = second, first
			}
			var injected atomic.Bool
			var estimate atomic.Uint64
			var secondEstimate atomic.Uint64
			c := proxy(t, env, nil, func(req rpcRequest, body []byte) ([]byte, error) {
				if req.Method == "eth_estimateGas" && injected.CompareAndSwap(false, true) {
					var response struct {
						Result hexutil.Uint64 `json:"result"`
					}
					if err := json.Unmarshal(body, &response); err != nil {
						return nil, err
					}
					estimate.Store(uint64(response.Result))
					if _, err := env.c.Send(env.ctx, first, nil, "confirmKey", id, address); err != nil {
						return nil, err
					}
					var current hexutil.Uint64
					if err := env.c.RPC.Client().CallContext(env.ctx, &current, "eth_estimateGas", req.Params[0]); err != nil {
						return nil, err
					}
					secondEstimate.Store(uint64(current))
				}
				return body, nil
			})
			r, err = c.Send(env.ctx, second, nil, "confirmKey", id, address)
			if err != nil {
				t.Fatal(err)
			}
			trade, err := env.c.Trade(env.ctx, tid, true)
			if err != nil || trade.Status != 3 || trade.EnclaveKey != address {
				t.Fatalf("key was not fixed: trade=%+v err=%v", trade, err)
			}
			// Receipt gasUsed is after gas refunds and can be below the minimum
			// execution budget; compare estimates at the two actual states instead.
			if !injected.Load() || estimate.Load() == 0 || secondEstimate.Load() <= estimate.Load() {
				t.Fatalf("test did not exercise a stale low estimate: first=%d second=%d", estimate.Load(), secondEstimate.Load())
			}
			t.Logf("first-branch estimate=%d, second-branch estimate=%d, receipt gas used=%d", estimate.Load(), secondEstimate.Load(), r.GasUsed)
		})
	}
}
