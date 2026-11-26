//go:build integration

package integration

import (
	"bytes"
	"context"
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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/experiment"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

func TestAdmissionGasCLIAndReadOnlyVerification(t *testing.T) {
	env := setupEnvironment(t, false)
	dir := t.TempDir()
	write := func(name string, v any) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if e := localio.WriteJSON(p, v); e != nil {
			t.Fatal(e)
		}
		return p
	}
	owner, ra := filepath.Join(dir, "owner.key"), filepath.Join(dir, "ra.key")
	for p, k := range map[string][]byte{owner: ethcrypto.FromECDSA(env.owner), ra: ethcrypto.FromECDSA(env.ra)} {
		if e := os.WriteFile(p, []byte(hex.EncodeToString(k)), 0600); e != nil {
			t.Fatal(e)
		}
	}
	cfg := env.c.Config
	cfg.Contract = common.Address{}
	cfg.CodeHash = common.Hash{}
	artifact, e := filepath.Abs("../contracts/out/TSC.sol/TSC.json")
	if e != nil {
		t.Fatal(e)
	}
	config := write("config.json", map[string]any{"chain": cfg, "secondary_rpc": cfg.RPC, "owner_key": owner, "auditor_key": ra, "dataset": write("dataset.json", env.data), "application": write("application.json", env.app), "artifact": artifact, "audits": 2, "accept_fixture": true, "max_cost_wei": "1000000000000000000"})
	binary := filepath.Join(dir, "admissiongasbench")
	build := exec.CommandContext(env.ctx, "go", "build", "-o", binary, "../6.3-certification/admissiongasbench")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	out, state := filepath.Join(dir, "results"), filepath.Join(dir, "private")
	cmd := exec.CommandContext(env.ctx, binary, "-config", config, "-out", out, "-state-dir", state, "-timeout", "40s")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("run: %v %s", e, b)
	}
	var record struct {
		Chain          json.RawMessage       `json:"chain"`
		SecondaryRPC   string                `json:"secondary_rpc"`
		Application    admission.Application `json:"application"`
		Actor          common.Address        `json:"auditor"`
		ExpectedAudits int                   `json:"expected_audits"`
		Code           []byte                `json:"-"`
	}
	raw, e := os.ReadFile(filepath.Join(out, "run.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &record); e != nil {
		t.Fatal(e)
	}
	var doc map[string]json.RawMessage
	if e = json.Unmarshal(raw, &doc); e != nil {
		t.Fatal(e)
	}
	var txs []experiment.GasTransaction
	var audits []experiment.GasAudit
	if e = json.Unmarshal(doc["transactions"], &txs); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(doc["audits"], &audits); e != nil {
		t.Fatal(e)
	}
	if len(txs) != 7 || len(audits) != 2 || record.ExpectedAudits != 2 {
		t.Fatal("incomplete trajectory")
	}
	var final experiment.GasFinalVerification
	if e = localio.ReadJSON(filepath.Join(out, "finalized-verification.json"), &final); e != nil {
		t.Fatal(e)
	}
	for i, g := range audits {
		var response admission.Response
		if e = localio.ReadJSON(filepath.Join(state, gFile("response", i+1)), &response); e != nil {
			t.Fatal(e)
		}
		if e = protocol.VerifySamples(env.app.Commitment, env.app.Description.Records, g.Challenge.Indices, response.Samples); e != nil {
			t.Fatal(e)
		}
		hash, _ := protocol.JSONHash(response)
		if hash != g.ResponseHash {
			t.Fatal("response evidence hash mismatch")
		}
		sum := uint64(0)
		for _, tx := range txs[1+3*i : 4+3*i] {
			sum += tx.Receipt.GasUsed
			r, e := env.c.RPC.TransactionReceipt(env.ctx, tx.Receipt.TxHash)
			if e != nil || r.GasUsed != tx.Receipt.GasUsed {
				t.Fatal("gas not measured from actual receipt", e)
			}
		}
		if sum != final.GasPerAudit[i] {
			t.Fatal("incorrect aggregate")
		}
	}
	manifest, e := os.ReadFile(filepath.Join(out, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{owner, ra, hex.EncodeToString(ethcrypto.FromECDSA(env.ra)), hex.EncodeToString(ethcrypto.FromECDSA(env.owner))} {
		if bytes.Contains(manifest, []byte(secret)) || bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret in public records")
		}
	}
	nonceBefore, e := env.c.RPC.PendingNonceAt(env.ctx, record.Actor)
	if e != nil {
		t.Fatal(e)
	}
	// Read-only verification rejects a modified gas observation and sends nothing.
	txs[1].Receipt.GasUsed++
	doc["transactions"], _ = json.Marshal(txs)
	bad, _ := json.Marshal(doc)
	if e = os.WriteFile(filepath.Join(out, "run.json"), bad, 0600); e != nil {
		t.Fatal(e)
	}
	cmd = exec.CommandContext(env.ctx, binary, "-verify-only", "-out", out, "-timeout", "20s")
	if b, e := cmd.CombinedOutput(); e == nil || !bytes.Contains(b, []byte("receipt differs")) {
		t.Fatalf("tampering accepted: %v %s", e, b)
	}
	nonceAfter, e := env.c.RPC.PendingNonceAt(env.ctx, record.Actor)
	if e != nil || nonceAfter != nonceBefore {
		t.Fatal("verification changed account nonce")
	}
}
func gFile(prefix string, n int) string { return fmt.Sprintf("%s-%03d.json", prefix, n) }

func TestAdmissionGasJournalFailurePreventsBroadcast(t *testing.T) {
	env := setupEnvironment(t, false)
	snap, e := protocol.NewSnapshot(env.data)
	if e != nil {
		t.Fatal(e)
	}
	stop := errors.New("journal unavailable")
	s := &experiment.GasSender{Client: env.c, Key: env.ra, MaxCost: big.NewInt(1_000_000_000_000_000_000), Emit: func(ev experiment.GasEvent) error {
		if ev.Type == "prepared" {
			return stop
		}
		return nil
	}}
	_, e = experiment.RunAdmissionGas(env.ctx, s, env.owner, experiment.AdmissionConfig{Application: env.app, Audits: 2, StateDir: t.TempDir(), AcceptFixture: true}, snap)
	if !errors.Is(e, stop) {
		t.Fatal("failed to stop before broadcast", e)
	}
	count, e := env.c.Call(env.ctx, false, "auditCount")
	if e != nil || count[0].(*big.Int).Sign() != 0 {
		t.Fatal("journal failure changed chain", e)
	}
}

func TestAdmissionGasVerificationRequiresFinalizedHeight(t *testing.T) {
	env := setupEnvironment(t, false)
	genesis, e := env.c.RPC.HeaderByNumber(env.ctx, big.NewInt(0))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
			t.Error(e)
			return
		}
		var value any
		switch req.Method {
		case "eth_chainId":
			value = "0x7a69"
		case "eth_getBlockByNumber":
			value = genesis
		default:
			t.Errorf("unexpected RPC before finality: %s", req.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": value})
	}))
	defer server.Close()
	node, e := ethclient.DialContext(context.Background(), server.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer node.Close()
	// Its low finalized height must prevent any completed-verification result.
	c := *env.c
	c.Config.Development = false
	c.RPC = node
	txs := make([]experiment.GasTransaction, 4)
	for i := range txs {
		txs[i].Receipt = &types.Receipt{BlockNumber: big.NewInt(100)}
	}
	_, e = experiment.VerifyAdmissionGas(env.ctx, &c, node, env.app, ethcrypto.PubkeyToAddress(env.ra.PublicKey), txs, []experiment.GasAudit{{Round: 1}}, []byte{1})
	if !errors.Is(e, experiment.ErrGasNotFinalized) {
		t.Fatalf("premature finality accepted: %v", e)
	}
}

// Public RPC providers may cache "latest" calls independently of receipts.
// This test rejects all unpinned eth_call and all gas estimates, so success
// requires receipt-block state reads and explicit transaction gas headroom.
func TestAdmissionGasUsesReceiptBlockState(t *testing.T) {
	env := setupEnvironment(t, false)
	target, err := url.Parse(env.c.Config.RPC)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body.Close()
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err = json.Unmarshal(body, &req); err != nil {
			t.Error(err)
			return
		}
		if req.Method == "eth_estimateGas" || (req.Method == "eth_call" && (len(req.Params) < 2 || string(req.Params[1]) == `"latest"`)) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": "unreliable latest state forbidden by test"}})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	cfg := env.c.Config
	cfg.RPC = server.URL
	c, err := chain.Dial(env.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	snapshot, err := protocol.NewSnapshot(env.data)
	if err != nil {
		t.Fatal(err)
	}
	sender := &experiment.GasSender{Client: c, Key: env.ra, MaxCost: big.NewInt(1_000_000_000_000_000_000), Emit: func(experiment.GasEvent) error { return nil }}
	audits, err := experiment.RunAdmissionGas(env.ctx, sender, env.owner, experiment.AdmissionConfig{Application: env.app, Audits: 2, StateDir: t.TempDir(), AcceptFixture: true}, snapshot)
	if err != nil || len(audits) != 2 || len(sender.Transactions) != 6 {
		t.Fatal("receipt-block path failed", err)
	}
	for _, tx := range sender.Transactions {
		if tx.Receipt.Status != 1 {
			t.Fatal("reverted transaction")
		}
	}
}
