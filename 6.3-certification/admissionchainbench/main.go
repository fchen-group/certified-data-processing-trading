// admissionchainbench runs an explicitly accepted B3 audit fixture on a dedicated
// test deployment, retaining the DO snapshot for the whole trajectory.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/experiment"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

type config struct {
	Chain         chain.Config `json:"chain"`
	OwnerKey      string       `json:"owner_key"`
	AuditorKey    string       `json:"auditor_key"`
	Dataset       string       `json:"dataset"`
	Application   string       `json:"application"`
	Audits        int          `json:"audits"`
	AcceptFixture bool         `json:"accept_fixture"`
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	return ethcrypto.HexToECDSA(strings.TrimSpace(string(raw)))
}

func run(args []string) error {
	f := flag.NewFlagSet("admissionchainbench", flag.ContinueOnError)
	cf := f.String("config", "", "chain, key paths, prepared dataset/application and fixture acceptance")
	out := f.String("out", "", "new public measurement directory; never overwritten")
	state := f.String("state-dir", "", "new private RA challenge-state directory, outside measurement output")
	procs := f.Int("gomaxprocs", 4, "Go execution parallelism")
	timeout := f.Duration("timeout", 0, "explicit whole-run timeout, including chain finality")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *out == "" || *state == "" || *procs <= 0 || *timeout <= 0 {
		return errors.New("new output/state directories, positive timeout and parallelism required")
	}
	outputPath, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	statePath, e := filepath.Abs(*state)
	if e != nil {
		return e
	}
	for _, pair := range [][2]string{{outputPath, statePath}, {statePath, outputPath}} {
		rel, e := filepath.Rel(pair[0], pair[1])
		if e != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return errors.New("public results and private RA state must be separate directories")
		}
	}
	var cfg config
	if e := localio.ReadJSON(*cf, &cfg); e != nil {
		return e
	}
	if !cfg.AcceptFixture || (!cfg.Chain.Development && cfg.Chain.ChainID != 11155111) {
		return errors.New("explicit fixture acceptance required; only local development or Sepolia is supported")
	}
	owner, e := readKey(cfg.OwnerKey)
	if e != nil {
		return e
	}
	ra, e := readKey(cfg.AuditorKey)
	if e != nil {
		return e
	}
	var a admission.Application
	if e := localio.ReadJSON(cfg.Application, &a); e != nil {
		return e
	}
	input, e := os.ReadFile(cfg.Dataset)
	if e != nil {
		return e
	}
	var d protocol.Dataset
	if e := protocol.StrictJSON(input, &d); e != nil {
		return e
	}
	runtime.GOMAXPROCS(*procs)
	start := time.Now()
	snapshot, e := protocol.NewSnapshot(d)
	buildNS := time.Since(start).Nanoseconds()
	if e != nil {
		return e
	}
	if e = a.Validate(); e != nil {
		return e
	}
	if a.Owner != ethcrypto.PubkeyToAddress(owner.PublicKey) || snapshot.Commitment() != a.Commitment || snapshot.Count() != a.Description.Records || cfg.Audits <= 0 || uint64(cfg.Audits) > a.Policy.MaxChallenges {
		return errors.New("owner, snapshot or requested audit count differs from application")
	}
	if e = localio.RequireNew(outputPath); e != nil {
		return e
	}
	if e = localio.RequireNew(statePath); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(outputPath), 0700); e != nil {
		return e
	}
	if e = os.Mkdir(outputPath, 0700); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(statePath), 0700); e != nil {
		return e
	}
	if e = os.Mkdir(statePath, 0700); e != nil {
		return e
	}
	info, _ := debug.ReadBuildInfo()
	binary, e := os.Executable()
	if e != nil {
		return e
	}
	bf, e := os.Open(binary)
	if e != nil {
		return e
	}
	h := sha256.New()
	_, e = io.Copy(h, bf)
	bf.Close()
	if e != nil {
		return e
	}
	finality := "finalized canonical block"
	if cfg.Chain.Development {
		finality = "latest canonical block; local development only"
	}
	manifest := map[string]any{
		"started_utc": time.Now().UTC(), "stage": "onchain-admission-fixture", "application": a,
		"audits": cfg.Audits, "accept_fixture": cfg.AcceptFixture, "chain_id": cfg.Chain.ChainID,
		"contract": cfg.Chain.Contract, "code_hash": cfg.Chain.CodeHash, "finality": finality,
		"os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(), "gomaxprocs": *procs,
		"build_info": info, "binary_sha256": hex.EncodeToString(h.Sum(nil)),
		"dataset_sha256": fmt.Sprintf("%x", sha256.Sum256(input)), "snapshot_builds": 1, "snapshot_ns": buildNS,
		"scope":               "sequential on-chain certifications; no calculation trades, TLS/network sample transfer or business review",
		"preparation":         "loads pre-generated records and salts; only retained snapshot construction is timed here",
		"call_ns":             "entire role API call, including applicable local processing, persistence, RPC and finality waiting",
		"respond_verify_ns":   "includes actual chain reads; use off-chain benchmark for isolated cryptographic timing",
		"coordinator_flow_ns": "audit wall time including event-journal persistence; not complete business turnaround",
		"wire_bytes":          "compact JSON sample/challenge envelopes, excluding business evidence and network headers",
		"reuse":               "first audit is shared; derive reuse from it and reaudit from measured prefixes; preparation counted once",
		"failure":             "stop and preserve journal/private state; no automatic retries or budget reset",
	}
	if e = localio.WriteJSON(filepath.Join(outputPath, "manifest.json"), manifest); e != nil {
		return e
	}
	journal, e := os.OpenFile(filepath.Join(outputPath, "events.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer journal.Close()
	emit := func(event experiment.AdmissionEvent) error {
		if e := json.NewEncoder(journal).Encode(event); e != nil {
			return e
		}
		return journal.Sync()
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, e := chain.Dial(ctx, cfg.Chain)
	if e != nil {
		return errors.Join(e, emit(experiment.AdmissionEvent{Type: "failure", Stage: "connect", Error: e.Error()}))
	}
	defer c.Close()
	return experiment.RunAdmission(ctx, c, owner, ra, experiment.AdmissionConfig{
		Application: a, Audits: cfg.Audits, StateDir: statePath, AcceptFixture: cfg.AcceptFixture,
	}, snapshot, emit)
}

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
