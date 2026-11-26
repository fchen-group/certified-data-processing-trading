// tradegasbench measures contract operations, not end-to-end SGX latency.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/experiment"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

type config struct {
	Chain         chain.Config  `json:"chain"`
	SecondaryRPC  string        `json:"secondary_rpc"`
	OwnerKey      string        `json:"owner_key"`
	BuyerKey      string        `json:"buyer_key"`
	Plan          string        `json:"plan"`
	Artifact      string        `json:"artifact"`
	DID           uint64        `json:"did"`
	Commitment    protocol.Hash `json:"commitment"`
	Source        protocol.Hash `json:"source"`
	Measurement   protocol.Hash `json:"measurement"`
	AcceptFixture bool          `json:"accept_fixture"`
	MaxCostWei    string        `json:"max_cost_wei_per_actor"`
}
type record struct {
	Chain        chain.Config            `json:"chain"`
	SecondaryRPC string                  `json:"secondary_rpc"`
	Run          *experiment.TradeGasRun `json:"run"`
}

func secondary(c chain.Config, endpoint string) error {
	u, e := url.Parse(endpoint)
	if e != nil || u.Host == "" || u.User != nil {
		return errors.New("invalid secondary RPC")
	}
	if c.Development {
		if u.Scheme != "http" || (u.Hostname() != "localhost" && !net.ParseIP(u.Hostname()).IsLoopback()) {
			return errors.New("local precheck requires loopback HTTP")
		}
	} else if u.Scheme != "https" || endpoint == c.RPC {
		return errors.New("independent HTTPS secondary RPC required")
	}
	return nil
}
func separated(a, b string) bool {
	for _, p := range [][2]string{{a, b}, {b, a}} {
		r, e := filepath.Rel(p[0], p[1])
		if e != nil || r == "." || (r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))) {
			return false
		}
	}
	return true
}
func verify(ctx context.Context, out, state, verificationConfig string) error {
	var r record
	if e := localio.ReadJSON(filepath.Join(out, "run.json"), &r); e != nil {
		return e
	}
	if verificationConfig != "" {
		var endpoints verificationRPC
		if e := localio.ReadJSON(verificationConfig, &endpoints); e != nil {
			return e
		}
		if e := endpoints.apply(&r); e != nil {
			return e
		}
	}
	if e := secondary(r.Chain, r.SecondaryRPC); e != nil {
		return e
	}
	secret, e := os.ReadFile(filepath.Join(state, "result.key"))
	if e != nil {
		return e
	}
	sk, e := hex.DecodeString(strings.TrimSpace(string(secret)))
	if e != nil {
		return e
	}
	c, e := chain.Dial(ctx, r.Chain)
	if e != nil {
		return e
	}
	defer c.Close()
	artifact, e := os.ReadFile(filepath.Join(out, "TSC.json"))
	if e != nil {
		return e
	}
	if e = checkArtifact(ctx, c, artifact); e != nil {
		return e
	}
	other, e := ethclient.DialContext(ctx, r.SecondaryRPC)
	if e != nil {
		return e
	}
	defer other.Close()
	for {
		v, e := experiment.VerifyTradeGas(ctx, c, other, r.Run, sk)
		if e == nil {
			path := filepath.Join(out, "verification.json")
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				evidence := struct {
					*experiment.TradeGasVerification
					Connections verificationRPC `json:"connections"`
				}{v, verificationRPC{r.Chain.RPC, r.Chain.RPCSPKI, r.SecondaryRPC}}
				if e = localio.WriteJSON(path, evidence); e != nil {
					return e
				}
			} else if err != nil {
				return err
			}
			fmt.Printf("VERIFIED development=%v transactions=%d trials=%d anchor=%d\n", v.Development, v.Transactions, len(v.Trials), v.AnchorNumber)
			return nil
		}
		if !errors.Is(e, experiment.ErrGasNotFinalized) {
			return e
		}
		fmt.Println("Waiting for common finalized anchor")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Second):
		}
	}
}
func run(args []string) error {
	f := flag.NewFlagSet("tradegasbench", flag.ContinueOnError)
	cf := f.String("config", "", "measurement configuration")
	output := f.String("out", "", "new measurement directory")
	state := f.String("state-dir", "", "separate private key directory")
	readonly := f.Bool("verify-only", false, "reverify existing records without loading account keys or sending transactions")
	verificationConfig := f.String("verification-config", "", "optional read-only RPC endpoints; requires -verify-only")
	timeout := f.Duration("timeout", 0, "explicit whole-run timeout")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *output == "" || *state == "" || *timeout <= 0 {
		return errors.New("output, separate state directory and positive timeout required")
	}
	if *verificationConfig != "" && !*readonly {
		return errors.New("verification-config requires verify-only")
	}
	out, e := filepath.Abs(*output)
	if e != nil {
		return e
	}
	private, e := filepath.Abs(*state)
	if e != nil {
		return e
	}
	if !separated(out, private) {
		return errors.New("public output and private state must be disjoint")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *readonly {
		return verify(ctx, out, private, *verificationConfig)
	}
	var cfg config
	if e = localio.ReadJSON(*cf, &cfg); e != nil {
		return e
	}
	if !cfg.AcceptFixture || cfg.Chain.Contract == (common.Address{}) || cfg.Chain.CodeHash == (common.Hash{}) || (!cfg.Chain.Development && cfg.Chain.ChainID != 11155111) {
		return errors.New("explicit fixture and pinned dedicated Sepolia/local contract required")
	}
	if e = secondary(cfg.Chain, cfg.SecondaryRPC); e != nil {
		return e
	}
	var plan experiment.TradeGasPlan
	if e = localio.ReadJSON(cfg.Plan, &plan); e != nil {
		return e
	}
	plan.DID, plan.Commitment, plan.Source, plan.Measurement = cfg.DID, cfg.Commitment, cfg.Source, cfg.Measurement
	if e = plan.Validate(); e != nil {
		return e
	}
	for _, fixture := range plan.Fixtures {
		data, err := os.ReadFile(fixture.Source)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, fixture.Plaintext) {
			return fmt.Errorf("%s plaintext differs from its frozen source file", fixture.Name)
		}
	}
	cap, ok := new(big.Int).SetString(cfg.MaxCostWei, 10)
	if !ok || cap.Sign() <= 0 {
		return errors.New("positive per-actor cumulative cost cap required")
	}
	ownerBytes, e := os.ReadFile(cfg.OwnerKey)
	if e != nil {
		return e
	}
	buyerBytes, e := os.ReadFile(cfg.BuyerKey)
	if e != nil {
		return e
	}
	owner, e := ethcrypto.HexToECDSA(strings.TrimSpace(string(ownerBytes)))
	if e != nil {
		return e
	}
	buyer, e := ethcrypto.HexToECDSA(strings.TrimSpace(string(buyerBytes)))
	if e != nil {
		return e
	}
	artifact, e := os.ReadFile(cfg.Artifact)
	if e != nil {
		return e
	}
	var art struct {
		ABI json.RawMessage `json:"abi"`
	}
	if e = json.Unmarshal(artifact, &art); e != nil {
		return e
	}
	var a, b any
	if e = json.Unmarshal(art.ABI, &a); e != nil {
		return e
	}
	if e = json.Unmarshal([]byte(chain.ABIJSON), &b); e != nil {
		return e
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		return errors.New("artifact and embedded ABI differ")
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
	receiptKey, e := ethcrypto.GenerateKey()
	if e != nil {
		return e
	}
	resultKey, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	for name, key := range map[string][]byte{"receipt.key": ethcrypto.FromECDSA(receiptKey), "result.key": resultKey.Bytes()} {
		if e = localio.Write(filepath.Join(private, name), []byte(hex.EncodeToString(key))); e != nil {
			return e
		}
	}
	if e = localio.WriteJSON(filepath.Join(out, "plan.json"), plan); e != nil {
		return e
	}
	if e = localio.Write(filepath.Join(out, "TSC.json"), artifact); e != nil {
		return e
	}
	binary, e := os.Executable()
	if e != nil {
		return e
	}
	binaryBytes, e := os.ReadFile(binary)
	if e != nil {
		return e
	}
	info, _ := debug.ReadBuildInfo()
	manifest := map[string]any{"started_utc": time.Now().UTC(), "purpose": "D1/D2 contract gas microbenchmark; not SGX or end-to-end timing", "development": cfg.Chain.Development, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "build_info": info, "artifact_sha256": fmt.Sprintf("%x", sha256.Sum256(artifact)), "binary_sha256": fmt.Sprintf("%x", sha256.Sum256(binaryBytes)), "cost_cap_wei_per_actor": cap.String(), "progression": "canonical inclusion and receipt-block state; batch-end common finalized anchor (development: latest)", "retries": "no automatic rebroadcast; stop and retain evidence on failure", "normal_total": "registerTrade + deposit + confirmKey/DO + confirmKey/DB + settle; withdrawal separate", "fixture": "public test result plaintext; fresh HPKE and signature per transaction"}
	if e = localio.WriteJSON(filepath.Join(out, "manifest.json"), manifest); e != nil {
		return e
	}
	journal, e := os.OpenFile(filepath.Join(out, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer journal.Close()
	emit := func(ev experiment.GasEvent) error {
		if e := json.NewEncoder(journal).Encode(ev); e != nil {
			return e
		}
		if e := journal.Sync(); e != nil {
			return e
		}
		if ev.Type == "included" {
			fmt.Printf("%d %s %s\n", ev.Round, ev.Method, ev.Hash)
		}
		return nil
	}
	states, e := os.OpenFile(filepath.Join(out, "states.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer states.Close()
	save := func(r *experiment.TradeGasRun) error {
		var v any = r
		if len(r.Trials) > 0 {
			v = map[string]any{"trial_number": len(r.Trials), "trial": r.Trials[len(r.Trials)-1]}
		}
		if e := json.NewEncoder(states).Encode(v); e != nil {
			return e
		}
		return states.Sync()
	}
	c, e := chain.Dial(ctx, cfg.Chain)
	if e != nil {
		return e
	}
	defer c.Close()
	if e = checkArtifact(ctx, c, artifact); e != nil {
		return e
	}
	s1 := &experiment.GasSender{Client: c, Key: owner, Emit: emit, MaxCost: cap}
	s2 := &experiment.GasSender{Client: c, Key: buyer, Emit: emit, MaxCost: cap}
	result, runErr := experiment.RunTradeGas(ctx, s1, s2, plan, receiptKey, resultKey.PublicKey().Bytes(), save)
	if e = localio.WriteJSON(filepath.Join(out, "run.json"), record{cfg.Chain, cfg.SecondaryRPC, result}); e != nil {
		return errors.Join(runErr, e)
	}
	if runErr != nil {
		_ = localio.WriteJSON(filepath.Join(out, "failure.json"), map[string]any{"at": time.Now().UTC(), "error": runErr.Error()})
		return runErr
	}
	if e = verify(ctx, out, private, ""); e != nil {
		_ = localio.WriteJSON(filepath.Join(out, "failure.json"), map[string]any{"at": time.Now().UTC(), "phase": "verification", "error": e.Error()})
		return e
	}
	return nil
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
