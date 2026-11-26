//go:build integration

package integration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

type rpcRequest struct {
	ID     json.RawMessage   `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// Hooks run against a real local EVM. They alter timing/availability, not valid
// signatures, contract execution, or the result expected by the buyer.
func proxy(t *testing.T, env *environment, before func(rpcRequest) error, after func(rpcRequest, []byte) ([]byte, error)) *chain.Client {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
			return
		}
		var req rpcRequest
		if e = json.Unmarshal(raw, &req); e != nil {
			t.Error(e)
			return
		}
		fail := func(e error) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": e.Error()}})
		}
		if before != nil {
			if e = before(req); e != nil {
				fail(e)
				return
			}
		}
		request, _ := http.NewRequestWithContext(r.Context(), "POST", env.c.Config.RPC, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		resp, e := http.DefaultClient.Do(request)
		if e != nil {
			fail(e)
			return
		}
		defer resp.Body.Close()
		body, e := io.ReadAll(resp.Body)
		if e == nil && after != nil {
			body, e = after(req, body)
		}
		if e != nil {
			fail(e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	cfg := env.c.Config
	cfg.RPC = s.URL
	c, e := chain.Dial(env.ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}

func (env *environment) advance(seconds int) error {
	var ignored any
	if e := env.c.RPC.Client().CallContext(env.ctx, &ignored, "evm_increaseTime", seconds); e != nil {
		return e
	}
	return env.c.RPC.Client().CallContext(env.ctx, &ignored, "evm_mine")
}

func (env *environment) remaining(t *testing.T, tid uint64, seconds uint64) {
	t.Helper()
	tr, e := env.c.Trade(env.ctx, tid, false)
	if e != nil {
		t.Fatal(e)
	}
	h, e := env.c.RPC.HeaderByNumber(env.ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = env.advance(int(tr.Deadline - seconds - h.Time)); e != nil {
		t.Fatal(e)
	}
}

func TestReviewLatePreparationNeverBroadcastsReceipt(t *testing.T) {
	for _, method := range []string{"eth_getTransactionCount", "eth_maxPriorityFeePerGas"} {
		t.Run(method, func(t *testing.T) {
			env := setup(t)
			tid, execution, _ := env.execute(t, 10, false)
			env.remaining(t, tid, 31)
			var advanced atomic.Bool
			var broadcasts atomic.Int64
			c := proxy(t, env, func(req rpcRequest) error {
				if req.Method == "eth_sendRawTransaction" {
					broadcasts.Add(1)
					return env.advance(12) // Under the configured 30-second confirmation bound.
				}
				return nil
			}, func(req rpcRequest, result []byte) ([]byte, error) {
				if req.Method == method && advanced.CompareAndSwap(false, true) {
					return result, env.advance(20)
				}
				return result, nil
			})
			if _, e := c.Settle(env.ctx, env.owner, tid, execution.Receipt, 30); e == nil {
				t.Fatal("late settlement accepted")
			}
			if !advanced.Load() || broadcasts.Load() != 0 {
				t.Fatalf("timing hook=%v broadcasts=%d", advanced.Load(), broadcasts.Load())
			}
			// A retry must prepare and check again, never reuse the original budget.
			if _, e := c.Settle(env.ctx, env.owner, tid, execution.Receipt, 30); e == nil || broadcasts.Load() != 0 {
				t.Fatal("retry leaked receipt")
			}
			if e := env.advance(12); e != nil {
				t.Fatal(e)
			}
			if _, e := env.c.Send(env.ctx, env.buyer, nil, "timeoutRefund", new(big.Int).SetUint64(tid)); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestReviewStateChangeDuringPreparation(t *testing.T) {
	env := setup(t)
	tid, execution, _ := env.execute(t, 10, false)
	var changed atomic.Bool
	var broadcasts atomic.Int64
	c := proxy(t, env, func(req rpcRequest) error {
		if req.Method == "eth_sendRawTransaction" {
			broadcasts.Add(1)
		}
		return nil
	}, func(req rpcRequest, result []byte) ([]byte, error) {
		if req.Method == "eth_getTransactionCount" && changed.CompareAndSwap(false, true) {
			if e := env.advance(601); e != nil {
				return nil, e
			}
			_, e := env.c.Send(env.ctx, env.buyer, nil, "timeoutRefund", new(big.Int).SetUint64(tid))
			return result, e
		}
		return result, nil
	})
	if _, e := c.Settle(env.ctx, env.owner, tid, execution.Receipt, 30); e == nil || broadcasts.Load() != 0 {
		t.Fatal("broadcast after state change")
	}
}

func TestReviewResultRecoveryWithPrunedHistory(t *testing.T) {
	env := setup(t)
	tid, execution, sk := env.execute(t, 10, false) // Execution server has now stopped.
	if _, e := env.c.Settle(env.ctx, env.owner, tid, execution.Receipt, 30); e != nil {
		t.Fatal(e)
	}
	var unavailable atomic.Bool
	var queries atomic.Int64
	c := proxy(t, env, func(req rpcRequest) error {
		if req.Method != "eth_getLogs" {
			return nil
		}
		queries.Add(1)
		var filter map[string]any
		if e := json.Unmarshal(req.Params[0], &filter); e != nil {
			return e
		}
		if filter["blockHash"] == nil || filter["fromBlock"] != nil || filter["toBlock"] != nil {
			return errors.New("pruned history unavailable; queries limited to one block")
		}
		if unavailable.Load() {
			return errors.New("pruned history unavailable")
		}
		return nil
	}, nil)
	encrypted, e := c.Result(env.ctx, tid)
	if e != nil {
		t.Fatal(e)
	}
	plaintext, e := protocol.DecryptResult(sk.Bytes(), encrypted, c.Domain(tid))
	if e != nil || string(plaintext) != `{"count":101,"above_threshold":96}` {
		t.Fatalf("wrong recovered result %s: %v", plaintext, e)
	}
	if queries.Load() != 1 {
		t.Fatal("result lookup did not use one bounded query")
	}
	unavailable.Store(true)
	if _, e = c.Result(env.ctx, tid); e == nil || !strings.Contains(e.Error(), "history unavailable") {
		t.Fatalf("missing history not reported: %v", e)
	}
}

func newAudit(t *testing.T, env *environment, batch string) uint64 {
	t.Helper()
	id, e := admission.Open(env.ctx, env.c, env.ra, env.app, protocol.H([]byte(batch)))
	if e != nil {
		t.Fatal(e)
	}
	return id
}

func assertChallengeCount(t *testing.T, env *environment, batch string, count uint64) {
	t.Helper()
	// ABI encoding for two static fields: padded address then bytes32 batch.
	b := make([]byte, 64)
	copy(b[12:32], env.app.Owner[:])
	h := protocol.H([]byte(batch))
	copy(b[32:], h[:])
	r, e := env.c.Call(env.ctx, true, "budgets", ethcrypto.Keccak256Hash(b))
	if e != nil || r[1].(uint64) != count {
		t.Fatalf("challenge count: %v %v", r, e)
	}
}

func TestReviewChallengePersistsBeforeBroadcastAndRecovers(t *testing.T) {
	env := setup(t)
	id := newAudit(t, env, "recover")
	dir := t.TempDir()
	var refuse atomic.Bool
	refuse.Store(true)
	c := proxy(t, env, func(req rpcRequest) error {
		if req.Method == "eth_sendRawTransaction" && refuse.Load() {
			return errors.New("connection failed before broadcast")
		}
		return nil
	}, nil)
	if _, e := admission.CreateChallenge(env.ctx, c, env.ra, id, env.app, dir); e == nil {
		t.Fatal("expected interrupted submission")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 1 {
		t.Fatal("candidate not persisted")
	}
	before, _ := os.ReadFile(files[0])
	assertChallengeCount(t, env, "recover", 0)
	refuse.Store(false)
	ch, e := admission.CreateChallenge(env.ctx, c, env.ra, id, env.app, dir)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(files[0])
	if !bytes.Equal(before, after) {
		t.Fatal("resampled after failed submission")
	}
	recovered, e := admission.CreateChallenge(env.ctx, env.c, env.ra, id, env.app, dir)
	if e != nil || fmt.Sprint(ch) != fmt.Sprint(recovered) {
		t.Fatal("fixed challenge not recovered", e)
	}
	assertChallengeCount(t, env, "recover", 1)
	// Foreign deployment/application state must not be reused.
	var state map[string]any
	_ = json.Unmarshal(before, &state)
	state["chain_id"] = 999
	bad, _ := json.Marshal(state)
	_ = os.WriteFile(files[0], bad, 0600)
	if _, e = admission.CreateChallenge(env.ctx, env.c, env.ra, id, env.app, dir); e == nil {
		t.Fatal("foreign candidate accepted")
	}
}

func TestReviewChallengeWriteFailureDoesNotConsumeBudget(t *testing.T) {
	env := setup(t)
	id := newAudit(t, env, "write-failure")
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if e := os.WriteFile(path, []byte("existing"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := admission.CreateChallenge(env.ctx, env.c, env.ra, id, env.app, path); e == nil {
		t.Fatal("accepted unusable storage")
	}
	assertChallengeCount(t, env, "write-failure", 0)
}

func TestReviewChallengeCLIOutputAndConfirmationRecovery(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "client")
	if out, e := exec.Command("go", "build", "-o", binary, "../prototype/client").CombinedOutput(); e != nil {
		t.Fatalf("build: %s %v", out, e)
	}
	for _, failure := range []string{"existing-output", "output-created-after-send", "confirmation-error"} {
		t.Run(failure, func(t *testing.T) {
			env := setup(t)
			id := newAudit(t, env, failure)
			dir := t.TempDir()
			output := filepath.Join(dir, "challenge.json")
			var injected atomic.Bool
			c := proxy(t, env, nil, func(req rpcRequest, result []byte) ([]byte, error) {
				if failure == "output-created-after-send" && req.Method == "eth_sendRawTransaction" && injected.CompareAndSwap(false, true) {
					return result, os.WriteFile(output, []byte("output race"), 0600)
				}
				if failure == "confirmation-error" && req.Method == "eth_getTransactionReceipt" && injected.CompareAndSwap(false, true) {
					return nil, errors.New("receipt query disconnected")
				}
				return result, nil
			})
			keyFile := filepath.Join(dir, "ra.key")
			_ = localio.Write(keyFile, []byte(hex.EncodeToString(ethcrypto.FromECDSA(env.ra))))
			cfg, app := filepath.Join(dir, "config.json"), filepath.Join(dir, "app.json")
			_ = localio.WriteJSON(cfg, map[string]any{"chain": c.Config, "account_key": keyFile})
			_ = localio.WriteJSON(app, env.app)
			run := func(out string) error {
				return exec.Command(binary, "audit-challenge", "-config", cfg, "-application", app, "-id", fmt.Sprint(id), "-output", out).Run()
			}
			if failure == "existing-output" {
				_ = os.WriteFile(output, []byte("keep"), 0600)
			}
			if e := run(output); e == nil {
				t.Fatal("expected local/confirmation failure")
			}
			count := uint64(1)
			if failure == "existing-output" {
				count = 0
			}
			assertChallengeCount(t, env, failure, count)
			if e := run(filepath.Join(dir, "recovered.json")); e != nil {
				t.Fatal("CLI could not recover", e)
			}
			var ch admission.Challenge
			if e := localio.ReadJSON(filepath.Join(dir, "recovered.json"), &ch); e != nil {
				t.Fatal(e)
			}
			if _, e := admission.CheckChallenge(env.ctx, env.c, env.app, ch); e != nil {
				t.Fatal(e)
			}
			assertChallengeCount(t, env, failure, 1)
		})
	}
}
