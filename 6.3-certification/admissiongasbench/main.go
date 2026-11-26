// admissiongasbench measures actual admission gas on a dedicated Sepolia TSC.
// Inclusion advances the experiment; finality is verified once for all results.
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
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/experiment"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

type config struct {
	Chain         chain.Config `json:"chain"`
	SecondaryRPC  string       `json:"secondary_rpc"`
	OwnerKey      string       `json:"owner_key"`
	AuditorKey    string       `json:"auditor_key"`
	Dataset       string       `json:"dataset"`
	Application   string       `json:"application"`
	Artifact      string       `json:"artifact"`
	Audits        int          `json:"audits"`
	AcceptFixture bool         `json:"accept_fixture"`
	MaxCostWei    string       `json:"max_cost_wei"`
}
type runRecord struct {
	Chain          chain.Config                `json:"chain"`
	SecondaryRPC   string                      `json:"secondary_rpc"`
	Application    admission.Application       `json:"application"`
	Actor          common.Address              `json:"auditor"`
	ExpectedAudits int                         `json:"expected_audits"`
	CreationCode   hexutil.Bytes               `json:"creation_code"`
	Transactions   []experiment.GasTransaction `json:"transactions"`
	Audits         []experiment.GasAudit       `json:"audits"`
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	return ethcrypto.HexToECDSA(strings.TrimSpace(string(b)))
}
func separate(a, b string) bool {
	for _, p := range [][2]string{{a, b}, {b, a}} {
		r, e := filepath.Rel(p[0], p[1])
		if e != nil || r == "." || (!strings.HasPrefix(r, ".."+string(filepath.Separator)) && r != "..") {
			return false
		}
	}
	return true
}
func validateSecondary(c chain.Config, endpoint string) error {
	u, e := url.Parse(endpoint)
	if e != nil || u.Host == "" || u.User != nil {
		return errors.New("invalid secondary RPC")
	}
	if !c.Development && (u.Scheme != "https" || endpoint == c.RPC) {
		return errors.New("independent HTTPS secondary RPC required")
	}
	return nil
}
func verify(ctx context.Context, out string) error {
	var r runRecord
	if e := localio.ReadJSON(filepath.Join(out, "run.json"), &r); e != nil {
		return e
	}
	if r.ExpectedAudits <= 0 || len(r.Audits) != r.ExpectedAudits || len(r.Transactions) != 1+3*r.ExpectedAudits {
		return errors.New("run is incomplete; refusing formal verification")
	}
	if e := validateSecondary(r.Chain, r.SecondaryRPC); e != nil {
		return e
	}
	c, e := chain.Dial(ctx, r.Chain)
	if e != nil {
		return e
	}
	defer c.Close()
	other, e := ethclient.DialContext(ctx, r.SecondaryRPC)
	if e != nil {
		return e
	}
	defer other.Close()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		v, e := experiment.VerifyAdmissionGas(ctx, c, other, r.Application, r.Actor, r.Transactions, r.Audits, r.CreationCode)
		if e == nil {
			if e = localio.WriteJSON(filepath.Join(out, "finalized-verification.json"), v); e != nil {
				return e
			}
			fmt.Printf("FINALIZED anchor=%d transactions=%d audits=%d gas_per_audit=%v\n", v.AnchorNumber, v.Transactions, v.Audits, v.GasPerAudit)
			return nil
		}
		if !errors.Is(e, experiment.ErrGasNotFinalized) {
			return e
		}
		fmt.Printf("%s waiting for common finalized anchor\n", time.Now().UTC().Format(time.RFC3339))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func run(args []string) error {
	f := flag.NewFlagSet("admissiongasbench", flag.ContinueOnError)
	cf := f.String("config", "", "new dedicated deployment and experiment configuration")
	output := f.String("out", "", "new public measurement directory")
	state := f.String("state-dir", "", "new private proof/challenge directory")
	verifyOnly := f.Bool("verify-only", false, "read-only finalization verification of an existing output directory")
	timeout := f.Duration("timeout", 0, "explicit whole-run timeout")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *output == "" || *timeout <= 0 {
		return errors.New("output and positive timeout required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	out, e := filepath.Abs(*output)
	if e != nil {
		return e
	}
	if *verifyOnly {
		return verify(ctx, out)
	}
	private, e := filepath.Abs(*state)
	if e != nil {
		return e
	}
	if *state == "" || !separate(out, private) {
		return errors.New("separate private state and public output directories required")
	}
	var cfg config
	if e = localio.ReadJSON(*cf, &cfg); e != nil {
		return e
	}
	if !cfg.AcceptFixture || cfg.Audits <= 0 || cfg.Chain.Contract != (common.Address{}) || cfg.Chain.CodeHash != (common.Hash{}) || (!cfg.Chain.Development && cfg.Chain.ChainID != 11155111) {
		return errors.New("explicit fixture, positive audits and fresh Sepolia/local contract required")
	}
	if e = validateSecondary(cfg.Chain, cfg.SecondaryRPC); e != nil {
		return e
	}
	maxCost, ok := new(big.Int).SetString(cfg.MaxCostWei, 10)
	if !ok || maxCost.Sign() <= 0 {
		return errors.New("positive cumulative test-ETH cap required")
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
	if e = localio.ReadJSON(cfg.Application, &a); e != nil {
		return e
	}
	if e = a.Validate(); e != nil {
		return e
	}
	input, e := os.ReadFile(cfg.Dataset)
	if e != nil {
		return e
	}
	var d protocol.Dataset
	if e = protocol.StrictJSON(input, &d); e != nil {
		return e
	}
	snapshot, e := protocol.NewSnapshot(d)
	if e != nil {
		return e
	}
	if snapshot.Commitment() != a.Commitment || snapshot.Count() != a.Description.Records || a.Owner != ethcrypto.PubkeyToAddress(owner.PublicKey) || uint64(cfg.Audits) > a.Policy.MaxChallenges {
		return errors.New("fixture application/snapshot mismatch")
	}
	if time.Now().Unix() >= int64(a.Policy.MaterialDeadline) {
		return errors.New("fixture deadline elapsed")
	}
	artifact, e := os.ReadFile(cfg.Artifact)
	if e != nil {
		return e
	}
	var art struct {
		ABI      json.RawMessage `json:"abi"`
		Bytecode struct {
			Object string `json:"object"`
		} `json:"bytecode"`
	}
	if e = json.Unmarshal(artifact, &art); e != nil {
		return e
	}
	var actual, expected any
	if e = json.Unmarshal(art.ABI, &actual); e != nil {
		return e
	}
	if e = json.Unmarshal([]byte(chain.ABIJSON), &expected); e != nil {
		return e
	}
	j1, _ := json.Marshal(actual)
	j2, _ := json.Marshal(expected)
	if string(j1) != string(j2) {
		return errors.New("artifact and embedded ABI mismatch")
	}
	code, e := hex.DecodeString(strings.TrimPrefix(art.Bytecode.Object, "0x"))
	if e != nil || len(code) == 0 {
		return errors.New("invalid creation bytecode")
	}
	for _, p := range []string{out, private} {
		if e = localio.RequireNew(p); e != nil {
			return e
		}
	}
	for _, p := range []string{out, private} {
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return e
		}
		if e = os.Mkdir(p, 0700); e != nil {
			return e
		}
	}
	binary, e := os.Executable()
	if e != nil {
		return e
	}
	executable, e := os.ReadFile(binary)
	if e != nil {
		return e
	}
	info, _ := debug.ReadBuildInfo()
	manifest := map[string]any{"started_utc": time.Now().UTC(), "purpose": "B3 actual gas only, one continuous 10-or-configured-audit trajectory; not protocol latency", "application": a, "audits": cfg.Audits, "accept_fixture": true, "snapshot_builds": 1, "dataset_sha256": fmt.Sprintf("%x", sha256.Sum256(input)), "artifact_sha256": fmt.Sprintf("%x", sha256.Sum256(artifact)), "binary_sha256": fmt.Sprintf("%x", sha256.Sum256(executable)), "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "build_info": info, "progression": "canonical inclusion per transaction; all transactions and final state checked at a common finalized anchor from two RPC providers", "disclosure": "public known fixture; private salts/proofs retained outside results", "retries": "none; failure preserves signed transaction journal; verify-only never sends", "maximum_cumulative_cost_wei": maxCost.String(), "scope": "deployment separately; three independent transactions per certification; no SGX or calculation trades; business approval supplied by operator"}
	if e = localio.WriteJSON(filepath.Join(out, "manifest.json"), manifest); e != nil {
		return e
	}
	journal, e := os.OpenFile(filepath.Join(out, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer journal.Close()
	emit := func(event experiment.GasEvent) error {
		if e := json.NewEncoder(journal).Encode(event); e != nil {
			return e
		}
		if e := journal.Sync(); e != nil {
			return e
		}
		fmt.Printf("%s %s round=%d method=%s hash=%s\n", time.Now().UTC().Format(time.RFC3339), event.Type, event.Round, event.Method, event.Hash)
		return nil
	}
	c, e := chain.Dial(ctx, cfg.Chain)
	if e != nil {
		return e
	}
	defer c.Close()
	s := &experiment.GasSender{Client: c, Key: ra, Emit: emit, MaxCost: maxCost}
	opts, e := s.Options(ctx)
	if e != nil {
		return e
	}
	actor := ethcrypto.PubkeyToAddress(ra.PublicKey)
	address, tx, _, e := bind.DeployContract(opts, chain.ABI, code, c.RPC, actor)
	if e != nil {
		return e
	}
	receipt, e := s.Broadcast(ctx, 0, "deploy", tx)
	if e != nil {
		return e
	}
	deployed, e := c.RPC.CodeAt(ctx, address, receipt.BlockNumber)
	if e != nil {
		return e
	}
	if len(deployed) == 0 {
		return errors.New("empty deployed code")
	}
	cc := cfg.Chain
	cc.Contract = address
	cc.CodeHash = ethcrypto.Keccak256Hash(deployed)
	if e = localio.WriteJSON(filepath.Join(out, "chain.json"), cc); e != nil {
		return e
	}
	// Reuse the pinned connection. Code was read at the deployment receipt's
	// block; a second latest-based Dial could observe a stale load-balanced view.
	contract := &chain.Client{RPC: c.RPC, Config: cc}
	s.Client = contract
	audits, runErr := experiment.RunAdmissionGas(ctx, s, owner, experiment.AdmissionConfig{Application: a, Audits: cfg.Audits, StateDir: private, AcceptFixture: true}, snapshot)
	record := runRecord{cc, cfg.SecondaryRPC, a, actor, cfg.Audits, code, s.Transactions, audits}
	if e = localio.WriteJSON(filepath.Join(out, "run.json"), record); e != nil {
		return errors.Join(runErr, e)
	}
	if runErr != nil {
		return runErr
	}
	return verify(ctx, out)
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
