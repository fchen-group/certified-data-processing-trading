//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/protocol"
	"certified-data-processing-trading/pkg/worker"
)

type environment struct {
	c                *chain.Client
	owner, buyer, ra *ecdsa.PrivateKey
	data             protocol.Dataset
	app              admission.Application
	did              uint64
	ctx              context.Context
}

func setup(t *testing.T) *environment {
	return setupEnvironment(t, true)
}

func setupEnvironment(t *testing.T, certify bool) *environment {
	return setupEnvironmentWithFork(t, certify, "", 90*time.Second)
}

func setupEnvironmentWithFork(t *testing.T, certify bool, fork string, timeout time.Duration) *environment {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	log, e := os.Create(filepath.Join(t.TempDir(), "anvil.log"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { log.Close() })
	args := []string{"--host", "127.0.0.1", "--port", fmt.Sprint(port), "--chain-id", "31337", "--silent"}
	if fork != "" {
		args = append(args, "--hardfork", fork)
	}
	cmd := exec.CommandContext(ctx, "anvil", args...)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	cfg := chain.Config{RPC: fmt.Sprintf("http://127.0.0.1:%d", port), ChainID: 31337, Development: true}
	var c *chain.Client
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		c, e = chain.Dial(ctx, cfg)
		if e == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	owner, _ := ethcrypto.GenerateKey()
	buyer, _ := ethcrypto.GenerateKey()
	ra, _ := ethcrypto.GenerateKey()
	for _, k := range []*ecdsa.PrivateKey{owner, buyer, ra} {
		var ok any
		e = c.RPC.Client().CallContext(ctx, &ok, "anvil_setBalance", ethcrypto.PubkeyToAddress(k.PublicKey), "0x3635c9adc5dea00000")
		if e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile("../contracts/out/TSC.sol/TSC.json")
	if e != nil {
		t.Fatal("run forge build first:", e)
	}
	var artifact struct {
		ABI      json.RawMessage `json:"abi"`
		Bytecode struct {
			Object string `json:"object"`
		} `json:"bytecode"`
	}
	if e = json.Unmarshal(raw, &artifact); e != nil {
		t.Fatal(e)
	}
	var expected, actual any
	_ = json.Unmarshal([]byte(chain.ABIJSON), &expected)
	_ = json.Unmarshal(artifact.ABI, &actual)
	ex, _ := json.Marshal(expected)
	ac, _ := json.Marshal(actual)
	if !bytes.Equal(ex, ac) {
		t.Fatal("embedded ABI out of date; refresh pkg/chain/tsc.abi.json from the compiled TSC artifact")
	}
	code, e := hex.DecodeString(artifact.Bytecode.Object[2:])
	if e != nil {
		t.Fatal(e)
	}
	opts, _ := bind.NewKeyedTransactorWithChainID(ra, big.NewInt(31337))
	opts.Context = ctx
	address, tx, _, e := bind.DeployContract(opts, chain.ABI, code, c.RPC, ethcrypto.PubkeyToAddress(ra.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Wait(ctx, tx); e != nil {
		t.Fatal(e)
	}
	deployed, e := c.RPC.CodeAt(ctx, address, nil)
	if e != nil {
		t.Fatal(e)
	}
	cfg.Contract = address
	cfg.CodeHash = ethcrypto.Keccak256Hash(deployed)
	cl, e := chain.Dial(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(cl.Close)
	records := make([][]byte, 101)
	for i := range records {
		records[i], _ = json.Marshal(analyzer.Record{ID: fmt.Sprint(i), Features: []float64{float64(i), 1}})
	}
	d, e := protocol.Prepare(records)
	if e != nil {
		t.Fatal(e)
	}
	tree, e := protocol.Build(d)
	if e != nil {
		t.Fatal(e)
	}
	header, e := cl.RPC.HeaderByNumber(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	app := admission.Application{Owner: ethcrypto.PubkeyToAddress(owner.PublicKey), Description: admission.Description{Version: "v1", Source: "controlled fixture", Batch: "batch1", Format: "work2.score-record.v1", Records: 101, Summary: "integration test; not business audit"}, Policy: protocol.Policy{Rho: .1, Epsilon: .01, MaxChallenges: 2, MaterialDeadline: header.Time + 300, AuditDeadline: header.Time + 600, BusinessRules: "manual test fixture approval"}, Commitment: tree.Commitment()}
	if !certify {
		return &environment{cl, owner, buyer, ra, d, app, 0, ctx}
	}
	aid, e := admission.Open(ctx, cl, ra, app, protocol.H([]byte("batch1")))
	if e != nil {
		t.Fatal(e)
	}
	challenge, e := admission.CreateChallenge(ctx, cl, ra, aid, app, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	response, e := admission.Respond(ctx, cl, owner, app, challenge, d)
	if e != nil {
		t.Fatal(e)
	}
	if e = admission.CheckResponse(ctx, cl, app, challenge, response); e != nil {
		t.Fatal(e)
	}
	response.Samples[0].Record = []byte("substituted")
	if e = admission.CheckResponse(ctx, cl, app, challenge, response); e == nil {
		t.Fatal("wrong sample accepted")
	}
	// Explicit test oracle for the out-of-scope manual business review.
	if _, e = cl.Send(ctx, ra, nil, "decideAudit", new(big.Int).SetUint64(aid), true); e != nil {
		t.Fatal(e)
	}
	audit, e := cl.Audit(ctx, aid, true)
	if e != nil {
		t.Fatal(e)
	}
	return &environment{cl, owner, buyer, ra, d, app, audit.Did.Uint64(), ctx}
}
func (env *environment) execute(t *testing.T, threshold float64, mutate bool) (uint64, worker.Execution, *ecdh.PrivateKey) {
	t.Helper()
	return env.executeTask(t, analyzer.Parameters{Weights: []float64{2, 1}, Threshold: threshold}, mutate)
}
func (env *environment) executeTask(t *testing.T, p analyzer.Parameters, mutate bool) (uint64, worker.Execution, *ecdh.PrivateKey) {
	t.Helper()
	c := env.c
	ctx := env.ctx
	r, e := c.Send(ctx, env.owner, nil, "registerTrade", new(big.Int).SetUint64(env.did), [32]byte(protocol.H([]byte("reviewed fixture source"))), [32]byte(protocol.H([]byte("development measurement"))), ethcrypto.PubkeyToAddress(env.buyer.PublicKey), big.NewInt(1000000), uint64(600))
	if e != nil {
		t.Fatal(e)
	}
	tid, e := c.EventID(r, "TradeRegistered")
	if e != nil {
		t.Fatal(e)
	}
	id := new(big.Int).SetUint64(tid)
	if _, e = c.Send(ctx, env.buyer, big.NewInt(1000000), "deposit", id); e != nil {
		t.Fatal(e)
	}
	d := env.data
	if mutate {
		d.Records = append([][]byte(nil), d.Records...)
		d.Records[0] = []byte(`{"id":"fake","features":[999,1]}`)
	}
	plaintext, _ := json.Marshal(d)
	key, _ := protocol.NewKey()
	encrypted, e := protocol.Seal(key, plaintext, c.Domain(tid).Bytes())
	if e != nil {
		t.Fatal(e)
	}
	s, e := worker.New(c, c.Domain(tid), func() ([]byte, error) { return bytes.Clone(encrypted), nil }, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = s.TLSConfig()
	ts.StartTLS()
	defer ts.Close() // Result recovery must work after the execution node stops.
	// Each role independently connects and pins the public development certificate.
	dc, e := worker.Connect(ctx, ts.URL, c.Domain(tid), protocol.Hash{}, nil, s.CertificatePEM())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(dc.Close)
	bc, e := worker.Connect(ctx, ts.URL, c.Domain(tid), protocol.Hash{}, nil, s.CertificatePEM())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(bc.Close)
	for _, role := range []struct {
		k *ecdsa.PrivateKey
		w *worker.Client
	}{{env.owner, dc}, {env.buyer, bc}} {
		if _, e = c.Send(ctx, role.k, nil, "confirmKey", id, role.w.KeyAddress()); e != nil {
			t.Fatal(e)
		}
	}
	sk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if e = bc.Send(ctx, env.buyer, "/db-input", worker.DBInput{Parameters: p, PublicKey: sk.PublicKey().Bytes()}, nil); e != nil {
		t.Fatal(e)
	}
	if e = dc.Send(ctx, env.owner, "/do-input", worker.DOInput{Key: key}, nil); e != nil {
		t.Fatal(e)
	}
	var execution worker.Execution
	if e = bc.Send(ctx, env.buyer, "/execute", struct{}{}, &execution); e == nil {
		t.Fatal("DB received receipt before settlement")
	}
	if e = dc.Send(ctx, env.owner, "/execute", struct{}{}, &execution); e != nil {
		t.Fatal(e)
	}
	digest := protocol.ReceiptDigest(c.Domain(tid), execution.Receipt.Commitment, execution.Receipt.Ciphertext)
	o, e := c.Call(ctx, true, "receiptDigest", id, [32]byte(execution.Receipt.Commitment), execution.Receipt.Ciphertext)
	if e != nil {
		t.Fatal(e)
	}
	if o[0].([32]byte) != digest {
		t.Fatal("Go/Solidity digest mismatch")
	}
	return tid, execution, sk
}
func TestEndToEnd(t *testing.T) {
	env := setup(t)
	for _, threshold := range []float64{10, 150} {
		tid, ex, sk := env.execute(t, threshold, false)
		if _, e := env.c.Result(env.ctx, tid); e == nil {
			t.Fatal("result visible before settlement")
		}
		receipt, e := env.c.Settle(env.ctx, env.owner, tid, ex.Receipt, 30)
		if e != nil {
			t.Fatal(e)
		}
		encrypted, e := env.c.Result(env.ctx, tid)
		if e != nil {
			t.Fatal(e)
		}
		result, e := protocol.DecryptResult(sk.Bytes(), encrypted, env.c.Domain(tid))
		if e != nil {
			t.Fatal(e)
		}
		expected, e := analyzer.Analyze(env.data.Records, analyzer.Parameters{Weights: []float64{2, 1}, Threshold: threshold})
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(result, expected) {
			t.Fatal("result differs from reference")
		}
		t.Logf("trade=%d reused_did=%d result=%s settle_gas=%d", tid, env.did, result, receipt.GasUsed)
		if _, e = env.c.Settle(env.ctx, env.owner, tid, ex.Receipt, 30); e == nil {
			t.Fatal("duplicate settlement")
		}
	}
	bal, e := env.c.Call(env.ctx, true, "balances", ethcrypto.PubkeyToAddress(env.owner.PublicKey))
	if e != nil || bal[0].(*big.Int).Cmp(big.NewInt(2000000)) != 0 {
		t.Fatal("incorrect credit", e)
	}
	if _, e = env.c.Send(env.ctx, env.owner, nil, "withdraw"); e != nil {
		t.Fatal(e)
	}
	bal, e = env.c.Call(env.ctx, true, "balances", ethcrypto.PubkeyToAddress(env.owner.PublicKey))
	if e != nil || bal[0].(*big.Int).Sign() != 0 {
		t.Fatal("credit not cleared", e)
	}
	t.Log("PASS: one certification, two independent parameterized trades, chain delivery, decryption and withdrawal")
}
func TestChangedInputCannotSettleAndBuyerCanRefund(t *testing.T) {
	env := setup(t)
	tid, ex, _ := env.execute(t, 10, true)
	id := new(big.Int).SetUint64(tid)
	if _, e := env.c.Settle(env.ctx, env.owner, tid, ex.Receipt, 30); e == nil {
		t.Fatal("honest preflight missed mismatch")
	}
	if _, e := env.c.Send(env.ctx, env.owner, nil, "settle", id, [32]byte(ex.Receipt.Commitment), ex.Receipt.Ciphertext, ex.Receipt.Signature); e == nil {
		t.Fatal("contract accepted changed input")
	}
	state, e := env.c.Trade(env.ctx, tid, true)
	if e != nil || state.Status != 3 {
		t.Fatal("invalid request changed state", e)
	}
	var ok any
	if e = env.c.RPC.Client().CallContext(env.ctx, &ok, "evm_increaseTime", 601); e != nil {
		t.Fatal(e)
	}
	if e = env.c.RPC.Client().CallContext(env.ctx, &ok, "evm_mine"); e != nil {
		t.Fatal(e)
	}
	if _, e = env.c.Send(env.ctx, env.buyer, nil, "timeoutRefund", id); e != nil {
		t.Fatal(e)
	}
	state, e = env.c.Trade(env.ctx, tid, true)
	if e != nil || state.Status != 5 {
		t.Fatal("refund not terminal", e)
	}
	if _, e = env.c.Result(env.ctx, tid); e == nil {
		t.Fatal("result event after refund")
	}
}
func TestWrongContractTrustAnchorRejected(t *testing.T) {
	env := setup(t)
	bad := env.c.Config
	bad.CodeHash = common.HexToHash("0x01")
	if c, e := chain.Dial(env.ctx, bad); e == nil {
		c.Close()
		t.Fatal("wrong code hash accepted")
	}
}
