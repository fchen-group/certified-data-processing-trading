//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/experiment"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

func tradePlan(t *testing.T, env *environment) experiment.TradeGasPlan {
	t.Helper()
	var p experiment.TradeGasPlan
	if e := localio.ReadJSON("../configs/trade-gas.json", &p); e != nil {
		t.Fatal(e)
	}
	for _, f := range p.Fixtures {
		b, e := os.ReadFile(filepath.Join("..", f.Source))
		if e != nil || !bytes.Equal(b, f.Plaintext) {
			t.Fatal("fixture bytes differ", e)
		}
	}
	p.DID, p.Commitment = env.did, env.app.Commitment
	p.Source, p.Measurement = protocol.H([]byte("trade-gas-source-fixture")), protocol.H([]byte("trade-gas-measurement-fixture"))
	return p
}

// Inclusion/state reads are current, but the backend serving estimates has a
// stale default view. Explicit block-hash reads remain available (after one
// transient miss), as on an RPC service whose backends synchronize separately.
func TestTradeGasLaggingEstimateView(t *testing.T) {
	env := setupEnvironmentWithFork(t, true, "prague", 90*time.Second)
	initial, err := env.c.RPC.HeaderByNumber(env.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(env.c.Config.RPC)
	if err != nil {
		t.Fatal(err)
	}
	forward := httputil.NewSingleHostReverseProxy(target)
	type observation struct {
		method string
		hash   common.Hash
	}
	var mu sync.Mutex
	var observed []observation
	var missedHash common.Hash
	misses, defaults := 0, 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		_ = r.Body.Close()
		var req struct {
			JSONRPC string            `json:"jsonrpc"`
			ID      json.RawMessage   `json:"id"`
			Method  string            `json:"method"`
			Params  []json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Error(err)
			return
		}
		if req.Method == "eth_estimateGas" {
			var call struct {
				Data  hexutil.Bytes `json:"data"`
				Input hexutil.Bytes `json:"input"`
			}
			if len(req.Params) == 0 || json.Unmarshal(req.Params[0], &call) != nil {
				t.Error("missing estimate input")
				return
			}
			input := call.Input
			if len(input) == 0 {
				input = call.Data
			}
			method, err := chain.ABI.MethodById(input)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			if len(req.Params) < 2 || string(req.Params[1]) == `"latest"` || string(req.Params[1]) == `"pending"` {
				defaults++
				selector, _ := json.Marshal(hexutil.EncodeBig(initial.Number))
				req.Params = []json.RawMessage{req.Params[0], selector}
				body, _ = json.Marshal(req)
			} else {
				var selector struct {
					BlockHash common.Hash `json:"blockHash"`
				}
				if json.Unmarshal(req.Params[1], &selector) != nil || selector.BlockHash == (common.Hash{}) {
					t.Errorf("estimate requires block hash: %s", req.Params[1])
				}
				if method.Name == "deposit" && misses == 0 {
					misses++
					missedHash = selector.BlockHash
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": "header not found"}})
					return
				}
				observed = append(observed, observation{method.Name, selector.BlockHash})
			}
			mu.Unlock()
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		forward.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	cfg := env.c.Config
	cfg.RPC = proxy.URL
	c, err := chain.Dial(env.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.RPC.Close()
	p := tradePlan(t, env)
	p.Repeats, p.Refunds = 1, 1
	receiptKey, _ := ethcrypto.GenerateKey()
	resultKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	owner := &experiment.GasSender{Client: c, Key: env.owner, MaxCost: big.NewInt(1e18), Emit: func(experiment.GasEvent) error { return nil }}
	buyer := &experiment.GasSender{Client: c, Key: env.buyer, MaxCost: big.NewInt(1e18), Emit: func(experiment.GasEvent) error { return nil }}
	staleRevert := false
	run, err := experiment.RunTradeGas(env.ctx, owner, buyer, p, receiptKey, resultKey.PublicKey().Bytes(), func(r *experiment.TradeGasRun) error {
		if !staleRevert && len(r.Trials) > 0 {
			trial := r.Trials[len(r.Trials)-1]
			if strings.HasPrefix(trial.Group, "D1/") && len(trial.Steps) == 1 {
				// Reproduce the old unpinned call after registration was checked.
				input, _ := chain.ABI.Pack("deposit", new(big.Int).SetUint64(trial.TID))
				_, err := c.RPC.EstimateGas(env.ctx, ethereum.CallMsg{From: r.Buyer, To: &cfg.Contract, Value: big.NewInt(1e12), Data: input})
				if err == nil || !strings.Contains(err.Error(), "deposit not allowed") {
					return fmt.Errorf("stale estimate did not reproduce revert: %v", err)
				}
				staleRevert = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !staleRevert || defaults != 1 || misses != 1 {
		t.Fatalf("stale=%v defaults=%d misses=%d", staleRevert, defaults, misses)
	}
	anchor, index, refunds := run.InitialHash, 0, 0
	for _, trial := range run.Trials {
		for _, step := range trial.Steps {
			method := step.Tx.Method
			if strings.HasPrefix(method, "confirmKey/") {
				method = "confirmKey"
			}
			if method != "settle" {
				if index >= len(observed) {
					t.Fatal("missing estimate")
				}
				o := observed[index]
				index++
				if o.method != method {
					t.Fatalf("estimate method=%s wanted=%s", o.method, method)
				}
				if method == "timeoutRefund" {
					h, err := env.c.RPC.HeaderByHash(env.ctx, o.hash)
					if err != nil || h.Time <= trial.Deadline || o.hash == anchor {
						t.Fatalf("refund estimated before expiry: header=%v error=%v", h, err)
					}
					refunds++
				} else if o.hash != anchor {
					t.Fatalf("%s estimated against wrong state", method)
				}
				if method == "deposit" && trial.Group == "D1/T1" && missedHash != o.hash {
					t.Fatal("retry changed requested block")
				}
			}
			anchor = step.State.BlockHash
		}
	}
	if index != len(observed) || refunds != 1 {
		t.Fatal("unexpected estimates or missing refund", index, len(observed), refunds)
	}
	if _, err := experiment.VerifyTradeGas(env.ctx, c, env.c.RPC, run, resultKey.Bytes()); err != nil {
		t.Fatal(err)
	}
	t.Logf("stale default estimate reverted; pinned driver completed %d trials, %d public estimates and a post-deadline refund", len(run.Trials), len(observed))
}

func TestTradeGasCLIAndReadOnlyVerification(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "tradegasbench")
	build := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", binary, "../6.5-chain/tradegasbench")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	env := setupEnvironmentWithFork(t, true, "prague", 5*time.Minute)
	p := tradePlan(t, env)
	for i := range p.Fixtures {
		p.Fixtures[i].Source, _ = filepath.Abs(filepath.Join("..", p.Fixtures[i].Source))
	}
	out, state := filepath.Join(dir, "results"), filepath.Join(dir, "private")
	if requested := os.Getenv("WORK2_TRADE_GAS_PRECHECK_OUT"); requested != "" {
		var e error
		out, e = filepath.Abs(requested)
		if e != nil {
			t.Fatal(e)
		}
		state = os.Getenv("WORK2_TRADE_GAS_PRECHECK_PRIVATE")
		if state == "" {
			t.Fatal("durable precheck needs a separate private-state directory")
		}
	}
	write := func(path string, v any) {
		t.Helper()
		if e := localio.WriteJSON(path, v); e != nil {
			t.Fatal(e)
		}
	}
	owner, buyer := filepath.Join(dir, "owner.key"), filepath.Join(dir, "buyer.key")
	for path, key := range map[string][]byte{owner: ethcrypto.FromECDSA(env.owner), buyer: ethcrypto.FromECDSA(env.buyer)} {
		if e := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0600); e != nil {
			t.Fatal(e)
		}
	}
	planPath := filepath.Join(dir, "plan.json")
	write(planPath, p)
	artifact, _ := filepath.Abs("../contracts/out/TSC.sol/TSC.json")
	configPath := filepath.Join(dir, "config.json")
	write(configPath, map[string]any{"chain": env.c.Config, "secondary_rpc": env.c.Config.RPC, "owner_key": owner, "buyer_key": buyer, "plan": planPath, "artifact": artifact, "did": p.DID, "commitment": p.Commitment, "source": p.Source, "measurement": p.Measurement, "accept_fixture": true, "max_cost_wei_per_actor": "1000000000000000000"})
	cmd := exec.CommandContext(env.ctx, binary, "-config", configPath, "-out", out, "-state-dir", state, "-timeout", "3m")
	log, e := cmd.CombinedOutput()
	if _, err := os.Stat(out); err == nil {
		_ = os.WriteFile(filepath.Join(out, "driver.log"), log, 0600)
	}
	if e != nil {
		t.Fatalf("driver: %v %s", e, log)
	}
	var record struct {
		Chain        chain.Config            `json:"chain"`
		SecondaryRPC string                  `json:"secondary_rpc"`
		Run          *experiment.TradeGasRun `json:"run"`
	}
	if e = localio.ReadJSON(filepath.Join(out, "run.json"), &record); e != nil {
		t.Fatal(e)
	}
	var v struct {
		experiment.TradeGasVerification
		Connections struct {
			RPC          string `json:"rpc"`
			RPCSPKI      string `json:"rpc_spki"`
			SecondaryRPC string `json:"secondary_rpc"`
		} `json:"connections"`
	}
	if e = localio.ReadJSON(filepath.Join(out, "verification.json"), &v); e != nil {
		t.Fatal(e)
	}
	if v.Transactions != 256 || len(v.Trials) != 44 || !v.Development {
		t.Fatalf("unexpected matrix: %d calls %d trials", v.Transactions, len(v.Trials))
	}
	seen := map[string]bool{}
	for i, trial := range record.Run.Trials {
		sum := uint64(0)
		for j, step := range trial.Steps {
			if trial.Group != "preparation" && trial.Group != "refund" && j < 5 {
				sum += step.Tx.Receipt.GasUsed
			}
		}
		if sum != v.Trials[i].NormalGas {
			t.Fatal("five-call total mismatch")
		}
		if len(trial.Ciphertext) > 0 {
			if seen[string(trial.Ciphertext)] {
				t.Fatal("ciphertext reused")
			}
			seen[string(trial.Ciphertext)] = true
			if v.Trials[i].CiphertextBytes != v.Trials[i].PlaintextBytes+48 || v.Trials[i].CalldataBytes > 120*1024 {
				t.Fatal("wrong lengths")
			}
		}
	}
	// Save deployment and certification receipts separately from measured calls.
	var preparation []*types.Receipt
	for n := uint64(1); n <= record.Run.InitialBlock; n++ {
		block, e := env.c.RPC.BlockByNumber(env.ctx, new(big.Int).SetUint64(n))
		if e != nil {
			t.Fatal(e)
		}
		for _, tx := range block.Transactions() {
			r, e := env.c.RPC.TransactionReceipt(env.ctx, tx.Hash())
			if e != nil {
				t.Fatal(e)
			}
			preparation = append(preparation, r)
		}
	}
	write(filepath.Join(out, "setup-receipts.json"), preparation)
	var version string
	var node any
	if e = env.c.RPC.Client().CallContext(env.ctx, &version, "web3_clientVersion"); e != nil {
		t.Fatal(e)
	}
	if e = env.c.RPC.Client().CallContext(env.ctx, &node, "anvil_nodeInfo"); e != nil {
		t.Fatal(e)
	}
	write(filepath.Join(out, "environment.json"), map[string]any{"client": version, "node": node, "hardfork": "prague", "chain_id": 31337, "scope": "local Anvil precheck only; both verification connections reach this one local node", "compiler_evm_target": "paris", "SGX": false, "Sepolia": false})
	// Account credentials are not needed for read-only verification.
	for _, path := range []string{owner, buyer} {
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
	}
	before, e := env.c.RPC.BlockNumber(env.ctx)
	if e != nil {
		t.Fatal(e)
	}
	cmd = exec.CommandContext(env.ctx, binary, "-verify-only", "-out", out, "-state-dir", state, "-timeout", "1m")
	log, e = cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(out, "readonly.log"), log, 0600)
	if e != nil {
		t.Fatalf("readonly: %v %s", e, log)
	}
	after, e := env.c.RPC.BlockNumber(env.ctx)
	if e != nil || after != before {
		t.Fatal("readonly changed chain", e)
	}
	keyHex, e := os.ReadFile(filepath.Join(state, "result.key"))
	if e != nil {
		t.Fatal(e)
	}
	sk, e := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if e != nil {
		t.Fatal(e)
	}
	other, e := ethclient.DialContext(env.ctx, env.c.Config.RPC)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	// Mutate copies only. Original observations remain intact.
	raw, _ := json.Marshal(record.Run)
	for _, test := range []struct {
		name   string
		mutate func(*experiment.TradeGasRun)
	}{
		{"gas", func(r *experiment.TradeGasRun) { r.Trials[1].Steps[4].Tx.Receipt.GasUsed++ }},
		{"missing_trial", func(r *experiment.TradeGasRun) { r.Trials = r.Trials[:len(r.Trials)-1] }},
		{"ciphertext", func(r *experiment.TradeGasRun) { r.Trials[1].Ciphertext[0] ^= 1 }},
		{"credit", func(r *experiment.TradeGasRun) { r.Trials[1].Steps[4].State.Credit = "0" }},
	} {
		var changed experiment.TradeGasRun
		_ = json.Unmarshal(raw, &changed)
		test.mutate(&changed)
		if _, e = experiment.VerifyTradeGas(env.ctx, env.c, other, &changed, sk); e == nil {
			t.Fatalf("accepted corrupt %s", test.name)
		}
	}
	after, e = env.c.RPC.BlockNumber(env.ctx)
	if e != nil || after != before {
		t.Fatal("tamper checks changed chain", e)
	}
	// A finalized head behind the observations must never produce valid results.
	genesis, e := env.c.RPC.HeaderByNumber(env.ctx, big.NewInt(0))
	if e != nil {
		t.Fatal(e)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x7a69"
		case "eth_getBlockByNumber":
			result = genesis
		default:
			t.Errorf("unexpected finality-gate call %s", q.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	defer proxy.Close()
	lagging, e := ethclient.DialContext(env.ctx, proxy.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer lagging.Close()
	production := *env.c
	production.Config.Development = false
	if _, e = experiment.VerifyTradeGas(env.ctx, &production, lagging, record.Run, sk); !errors.Is(e, experiment.ErrGasNotFinalized) {
		t.Fatalf("finality gate: %v", e)
	}
	write(filepath.Join(out, "checks.json"), map[string]any{"matrix": true, "five_call_totals": true, "fresh_ciphertext": true, "readonly_without_account_keys": true, "tampered_gas_rejected": true, "incomplete_matrix_rejected": true, "tampered_ciphertext_rejected": true, "tampered_credit_rejected": true, "unfinalized_rejected": true})
	// Preserve a local state snapshot; it does not replace the receipt history.
	if os.Getenv("WORK2_TRADE_GAS_PRECHECK_OUT") != "" {
		var dump string
		if e = env.c.RPC.Client().CallContext(env.ctx, &dump, "anvil_dumpState"); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, "anvil-state.hex"), []byte(dump), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("local precheck: %d transactions, %d result ciphertexts, %d Ready refunds; evidence %s", v.Transactions, len(seen), p.Refunds, out)
}

func TestTradeGasFailureBeforeBroadcast(t *testing.T) {
	env := setup(t)
	p := tradePlan(t, env)
	receiptKey, _ := ethcrypto.GenerateKey()
	resultKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	before, _ := env.c.RPC.BlockNumber(env.ctx)
	injected := errors.New("journal storage failure")
	owner := &experiment.GasSender{Client: env.c, Key: env.owner, MaxCost: big.NewInt(1e18), Emit: func(experiment.GasEvent) error { return injected }}
	buyer := &experiment.GasSender{Client: env.c, Key: env.buyer, MaxCost: big.NewInt(1e18), Emit: func(experiment.GasEvent) error { return nil }}
	r, e := experiment.RunTradeGas(env.ctx, owner, buyer, p, receiptKey, resultKey.PublicKey().Bytes(), func(*experiment.TradeGasRun) error { return nil })
	if !errors.Is(e, injected) || len(r.Trials) != 1 || len(r.Trials[0].Steps) != 0 {
		t.Fatalf("journal failure: %v", e)
	}
	after, _ := env.c.RPC.BlockNumber(env.ctx)
	if before != after {
		t.Fatal("broadcast before durable journal")
	}
	ctx, cancel := context.WithCancel(env.ctx)
	cancel()
	if _, e = experiment.RunTradeGas(ctx, owner, buyer, p, receiptKey, resultKey.PublicKey().Bytes(), func(*experiment.TradeGasRun) error { return nil }); e == nil {
		t.Fatal("cancelled run continued")
	}
}

func TestTradeGasStateCostPreconditions(t *testing.T) {
	env := setupEnvironmentWithFork(t, true, "prague", 90*time.Second)
	p := tradePlan(t, env)
	receiptKey, _ := ethcrypto.GenerateKey()
	resultKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	gas := make([]map[string]uint64, 2)
	var evidence []map[string]any
	for i := 0; i < 2; i++ {
		r, e := env.c.Send(env.ctx, env.owner, nil, "registerTrade", new(big.Int).SetUint64(p.DID), [32]byte(p.Source), [32]byte(p.Measurement), ethcrypto.PubkeyToAddress(env.buyer.PublicKey), big.NewInt(1e12), uint64(3600))
		if e != nil {
			t.Fatal(e)
		}
		tid, e := env.c.EventID(r, "TradeRegistered")
		if e != nil {
			t.Fatal(e)
		}
		gas[i] = map[string]uint64{"registerTrade": r.GasUsed}
		receipts := []*types.Receipt{r}
		r, e = env.c.Send(env.ctx, env.buyer, big.NewInt(1e12), "deposit", new(big.Int).SetUint64(tid))
		if e != nil {
			t.Fatal(e)
		}
		receipts = append(receipts, r)
		for _, key := range []bool{true, false} {
			signer := env.buyer
			if key {
				signer = env.owner
			}
			r, e = env.c.Send(env.ctx, signer, nil, "confirmKey", new(big.Int).SetUint64(tid), ethcrypto.PubkeyToAddress(receiptKey.PublicKey))
			if e != nil {
				t.Fatal(e)
			}
			receipts = append(receipts, r)
		}
		cipher, e := protocol.EncryptResult(resultKey.PublicKey().Bytes(), p.Fixtures[1].Plaintext, env.c.Domain(tid))
		if e != nil {
			t.Fatal(e)
		}
		sig, e := protocol.Sign(receiptKey, protocol.ReceiptDigest(env.c.Domain(tid), p.Commitment, cipher))
		if e != nil {
			t.Fatal(e)
		}
		r, e = env.c.Send(env.ctx, env.owner, nil, "settle", new(big.Int).SetUint64(tid), [32]byte(p.Commitment), cipher, sig)
		if e != nil {
			t.Fatal(e)
		}
		gas[i]["settle"] = r.GasUsed
		receipts = append(receipts, r)
		evidence = append(evidence, map[string]any{"tid": tid, "credit_before_wei": fmt.Sprint(int64(i) * 1e12), "receipts": receipts})
	}
	// State initialization costs dominate the small random-calldata differences.
	if gas[0]["registerTrade"] <= gas[1]["registerTrade"]+16000 || gas[0]["settle"] <= gas[1]["settle"]+16000 {
		t.Fatalf("state cost distinction not observed: %v", gas)
	}
	if out := os.Getenv("WORK2_TRADE_GAS_PRECHECK_OUT"); out != "" {
		if e := localio.WriteJSON(filepath.Join(out, "state-cost-check.json"), map[string]any{"scope": "separate local fixture; not part of D1/D2 means", "gas": gas, "evidence": evidence}); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("separate state precheck gas: %v", gas)
}
