//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/experiment"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

func TestAdmissionExperimentCLIRecordsRealChainTrajectory(t *testing.T) {
	env := setupEnvironment(t, false)
	dir := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := localio.WriteJSON(path, value); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ownerPath, raPath := filepath.Join(dir, "owner.key"), filepath.Join(dir, "ra.key")
	for path, key := range map[string][]byte{ownerPath: ethcrypto.FromECDSA(env.owner), raPath: ethcrypto.FromECDSA(env.ra)} {
		if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := write("config.json", map[string]any{
		"chain": env.c.Config, "owner_key": ownerPath, "auditor_key": raPath,
		"dataset": write("dataset.json", env.data), "application": write("application.json", env.app),
		"audits": 2, "accept_fixture": true,
	})
	binary := filepath.Join(dir, "admissionchainbench")
	build := exec.CommandContext(env.ctx, "go", "build", "-o", binary, "../6.3-certification/admissionchainbench")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	out, state := filepath.Join(dir, "results"), filepath.Join(dir, "private-state")
	command := exec.CommandContext(env.ctx, binary, "-config", config, "-out", out, "-state-dir", state, "-timeout", "30s")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("driver: %v\n%s", err, output)
	}
	var manifest struct {
		SnapshotBuilds int   `json:"snapshot_builds"`
		SnapshotNS     int64 `json:"snapshot_ns"`
	}
	// The manifest deliberately includes additional provenance fields.
	raw, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SnapshotBuilds != 1 || manifest.SnapshotNS <= 0 {
		t.Fatal("missing one-time snapshot measurement")
	}
	for _, secret := range []string{ownerPath, raPath, hex.EncodeToString(ethcrypto.FromECDSA(env.owner)), hex.EncodeToString(ethcrypto.FromECDSA(env.ra))} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("public manifest exposed key material/path")
		}
	}
	raw, err = os.ReadFile(filepath.Join(out, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	var audits []experiment.ChainAudit
	txs, complete := 0, false
	seen := map[uint64]bool{}
	for scanner.Scan() {
		var event experiment.AdmissionEvent
		if err := protocol.StrictJSON(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		switch event.Type {
		case "failure":
			t.Fatal(event.Error)
		case "transaction":
			txs++
			r, err := env.c.RPC.TransactionReceipt(env.ctx, event.Transaction.Hash)
			if err != nil {
				t.Fatal(err)
			}
			if r.GasUsed == 0 || r.GasUsed != event.Transaction.GasUsed || r.BlockHash != event.Transaction.BlockHash || r.BlockNumber.Uint64() != event.Transaction.BlockNumber {
				t.Fatal("logged transaction differs from actual chain receipt")
			}
		case "audit":
			audits = append(audits, *event.Audit)
		case "complete":
			complete = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !complete || txs != 6 || len(audits) != 2 {
		t.Fatalf("incomplete trajectory: %d transactions, %d audits", txs, len(audits))
	}
	m, err := protocol.SampleSize(env.app.Description.Records, env.app.Policy.Rho, env.app.Policy.Epsilon)
	if err != nil {
		t.Fatal(err)
	}
	for i, result := range audits {
		if !result.Verified || result.Round != i+1 || result.Commitment != env.app.Commitment || result.ChallengesUsed != uint64(i+1) || len(result.Transactions) != 3 || uint64(len(result.Challenge.Indices)) != m || result.ResponseWireBytes <= 0 {
			t.Fatal("incorrect measured audit")
		}
		for _, index := range result.Challenge.Indices {
			seen[index] = true
		}
		if result.CumulativeDistinct != len(seen) {
			t.Fatal("incorrect cumulative disclosure")
		}
		closed, err := admission.Check(env.ctx, env.c, result.AID, env.app)
		if err != nil {
			t.Fatal(err)
		}
		if closed.Status != 3 || closed.Did.Uint64() != result.DID {
			t.Fatal("result differs from certification state")
		}
	}
	assertChallengeCount(t, env, "batch1", 2)
	// A second invocation must not silently reset a batch budget or overwrite results.
	command = exec.CommandContext(env.ctx, binary, "-config", config, "-out", filepath.Join(dir, "second-results"), "-state-dir", filepath.Join(dir, "second-state"), "-timeout", "30s")
	if output, err := command.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("fresh isolated")) {
		t.Fatalf("reused deployment accepted: %v %s", err, output)
	}
	assertChallengeCount(t, env, "batch1", 2)
}

func TestAdmissionExperimentStopsWithoutApprovingOrRedrawing(t *testing.T) {
	env := setupEnvironment(t, false)
	snapshot, err := protocol.NewSnapshot(env.data)
	if err != nil {
		t.Fatal(err)
	}
	cfg := experiment.AdmissionConfig{Application: env.app, Audits: 2, StateDir: t.TempDir(), AcceptFixture: true}
	var events []experiment.AdmissionEvent
	emit := func(event experiment.AdmissionEvent) error { events = append(events, event); return nil }
	bad := cfg
	bad.Audits = 3
	if err := experiment.RunAdmission(env.ctx, env.c, env.owner, env.ra, bad, snapshot, emit); err == nil {
		t.Fatal("budget excess accepted")
	}
	bad = cfg
	bad.AcceptFixture = false
	if err := experiment.RunAdmission(env.ctx, env.c, env.owner, env.ra, bad, snapshot, emit); err == nil {
		t.Fatal("implicit business approval accepted")
	}
	if err := experiment.RunAdmission(env.ctx, env.c, env.buyer, env.ra, cfg, snapshot, emit); err == nil {
		t.Fatal("wrong owner accepted")
	}
	count, err := env.c.Call(env.ctx, true, "auditCount")
	if err != nil || count[0].(*big.Int).Sign() != 0 {
		t.Fatal("preflight failure changed chain")
	}
	stop := errors.New("test interruption before response")
	emit = func(event experiment.AdmissionEvent) error {
		events = append(events, event)
		if event.Type == "stage" && event.Stage == "respond-and-verify" {
			return stop
		}
		return nil
	}
	if err := experiment.RunAdmission(env.ctx, env.c, env.owner, env.ra, cfg, snapshot, emit); !errors.Is(err, stop) {
		t.Fatalf("unexpected interruption: %v", err)
	}
	last := events[len(events)-1]
	if last.Type != "failure" || last.AID == 0 {
		t.Fatal("interruption was not recorded")
	}
	audit, err := admission.Check(env.ctx, env.c, last.AID, env.app)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Status != 2 || audit.Did.Sign() != 0 {
		t.Fatal("interrupted audit certified")
	}
	ch, receipt, err := admission.CreateChallengeWithReceipt(env.ctx, env.c, env.ra, last.AID, env.app, cfg.StateDir)
	if err != nil || receipt != nil {
		t.Fatal("recovery sent or counted another transaction", err)
	}
	ch2, receipt, err := admission.CreateChallengeWithReceipt(env.ctx, env.c, env.ra, last.AID, env.app, cfg.StateDir)
	if err != nil || receipt != nil || !reflect.DeepEqual(ch, ch2) {
		t.Fatal("recovery redrew challenge", err)
	}
	assertChallengeCount(t, env, "batch1", 1)
}
