// Unified CLI client shared by the Data Owner (DO), Data Buyer (DB), and Review Authority (RA).
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/platform"
	"certified-data-processing-trading/pkg/protocol"
	"certified-data-processing-trading/pkg/worker"
)

type config struct {
	Chain                  chain.Config `json:"chain"`
	AccountKey             string       `json:"account_key"`
	WorkerURL              string       `json:"worker_url"`
	DevelopmentCertificate string       `json:"development_certificate"`
}

type agreement struct {
	DID         uint64         `json:"did"`
	Owner       common.Address `json:"owner"`
	Buyer       common.Address `json:"buyer"`
	Source      protocol.Hash  `json:"source_hash"`
	Measurement protocol.Hash  `json:"measurement"`
	Price       string         `json:"price_wei"`
	Duration    uint64         `json:"duration_seconds"`
}

type decision struct {
	Accepted          bool   `json:"accepted"`
	ReceivedAt        uint64 `json:"received_at"`
	EvidenceReference string `json:"evidence_reference"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func run() (runErr error) {
	if len(os.Args) < 2 {
		return errors.New("commands: keygen, prepare, deploy, audit-open, audit-challenge, audit-respond, audit-decide, audit-expire, trade-register, trade-check, deposit, attest, confirm-key, encrypt-input, do-input, db-input, execute, settle, decrypt, refund, withdraw, inspect")
	}
	action := os.Args[1]
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	cf := f.String("config", "", "role configuration JSON")
	in := f.String("input", "", "command input JSON/file")
	out := f.String("output", "", "new output file")
	id := f.Uint64("id", 0, "audit or trade ID")
	dataset := f.String("dataset", "", "DO's private normalized records and salts")
	policy := f.String("policy", "", "audit policy JSON")
	description := f.String("description", "", "description JSON")
	appFile := f.String("application", "", "public application JSON")
	challengeFile := f.String("challenge", "", "challenge JSON")
	stateDir := f.String("state-dir", "", "RA private challenge recovery directory; defaults beside account key")
	responseFile := f.String("response", "", "sample response JSON")
	batch := f.String("batch", "", "RA-identified stable source-batch ID")
	params := f.String("parameters", "", "DB's private parameter JSON")
	keyFile := f.String("secret-file", "", "local secret key file, never hosted on compute node")
	margin := f.Uint64("margin", 0, "required settlement time margin in seconds; explicitly configure for the target chain")
	timingsPath := f.String("timings", "", "optional new C1 timing output for attest, confirm-key, db-input or do-input")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	measured := map[string]int64{}
	if *timingsPath != "" {
		if action != "attest" && action != "confirm-key" && action != "db-input" && action != "do-input" {
			return errors.New("timings supported only for C1 commands")
		}
		if e := localio.RequireNew(*timingsPath); e != nil {
			return e
		}
		defer func() {
			if runErr == nil {
				runErr = localio.WriteJSON(*timingsPath, map[string]any{"action": action, "tid": *id, "nanoseconds": measured})
			}
		}()
	}
	if action == "keygen" {
		k, e := ethcrypto.GenerateKey()
		if e != nil {
			return e
		}
		if e = localio.Write(*out, []byte(hex.EncodeToString(ethcrypto.FromECDSA(k))+"\n")); e != nil {
			return e
		}
		fmt.Println(ethcrypto.PubkeyToAddress(k.PublicKey))
		return nil
	}
	var cfg config
	if e := localio.ReadJSON(*cf, &cfg); e != nil {
		return e
	}
	var key *ecdsa.PrivateKey
	if cfg.AccountKey != "" {
		raw, e := os.ReadFile(cfg.AccountKey)
		if e != nil {
			return e
		}
		key, e = ethcrypto.HexToECDSA(strings.TrimSpace(string(raw)))
		if e != nil {
			return e
		}
	}
	requireKey := func() error {
		if key == nil {
			return errors.New("account key required")
		}
		return nil
	}
	if action == "prepare" {
		if e := requireKey(); e != nil {
			return e
		}
		var des admission.Description
		if e := localio.ReadJSON(*description, &des); e != nil {
			return e
		}
		raw, e := loadInputRecords(*in, des.Format)
		if e != nil {
			return e
		}
		d, e := protocol.Prepare(raw)
		if e != nil {
			return e
		}
		tree, e := protocol.Build(d)
		if e != nil {
			return e
		}
		var p protocol.Policy
		if e = localio.ReadJSON(*policy, &p); e != nil {
			return e
		}
		if des.Records != uint64(len(raw)) {
			return errors.New("description record count or format mismatch")
		}
		a := admission.Application{Owner: ethcrypto.PubkeyToAddress(key.PublicKey), Description: des, Policy: p, Commitment: tree.Commitment()}
		if e = a.Validate(); e != nil {
			return e
		}
		if *appFile == "" || *dataset == "" {
			return errors.New("application and dataset paths required")
		}
		if e = localio.WriteJSON(*dataset, d); e != nil {
			return e
		}
		return localio.WriteJSON(*appFile, a)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	c, e := chain.Dial(ctx, cfg.Chain)
	if e != nil {
		return e
	}
	defer c.Close()
	n := new(big.Int).SetUint64(*id)
	loadAdmission := func() (admission.Application, admission.Challenge, error) {
		var a admission.Application
		var ch admission.Challenge
		e := localio.ReadJSON(*appFile, &a)
		if e == nil && *challengeFile != "" {
			e = localio.ReadJSON(*challengeFile, &ch)
		}
		return a, ch, e
	}
	connect := func(ready bool) (*worker.Client, error) {
		t, e := c.Trade(ctx, *id, true)
		if e != nil {
			return nil, e
		}
		if t.Status != 2 && t.Status != 3 {
			return nil, errors.New("trade must be funded or ready")
		}
		var dev []byte
		if cfg.DevelopmentCertificate != "" {
			if !cfg.Chain.Development {
				return nil, errors.New("development certificate forbidden with production chain")
			}
			dev, e = os.ReadFile(cfg.DevelopmentCertificate)
			if e != nil {
				return nil, e
			}
		}
		connectStart := time.Now()
		w, e := worker.Connect(ctx, cfg.WorkerURL, c.Domain(*id), protocol.Hash(t.Measurement), platform.Verify, dev)
		measured["report_fetch_verify"] = time.Since(connectStart).Nanoseconds()
		if e != nil {
			return nil, e
		}
		if ready && (t.Status != 3 || w.KeyAddress() != t.EnclaveKey) {
			w.Close()
			return nil, errors.New("worker key does not match fixed chain key")
		}
		return w, nil
	}
	if action != "attest" && action != "inspect" && action != "trade-check" && action != "decrypt" {
		if e = requireKey(); e != nil {
			return e
		}
	}
	switch action {
	case "deploy":
		var artifact struct {
			Bytecode struct {
				Object string `json:"object"`
			} `json:"bytecode"`
		}
		raw, e := os.ReadFile(*in)
		if e != nil {
			return e
		}
		if e = json.Unmarshal(raw, &artifact); e != nil {
			return e
		}
		code, e := hex.DecodeString(strings.TrimPrefix(artifact.Bytecode.Object, "0x"))
		if e != nil || len(code) == 0 {
			return errors.New("invalid contract artifact")
		}
		opts, e := bind.NewKeyedTransactorWithChainID(key, new(big.Int).SetUint64(cfg.Chain.ChainID))
		if e != nil {
			return e
		}
		opts.Context = ctx
		addr, tx, _, e := bind.DeployContract(opts, chain.ABI, code, c.RPC, ethcrypto.PubkeyToAddress(key.PublicKey))
		if e != nil {
			return e
		}
		if _, e = c.Wait(ctx, tx); e != nil {
			return e
		}
		deployed, e := c.RPC.CodeAt(ctx, addr, nil)
		if e != nil {
			return e
		}
		cfg.Chain.Contract = addr
		cfg.Chain.CodeHash = ethcrypto.Keccak256Hash(deployed)
		return localio.WriteJSON(*out, cfg.Chain)
	case "audit-open":
		a, _, e := loadAdmission()
		if e != nil {
			return e
		}
		if *batch == "" {
			return errors.New("RA-identified batch required")
		}
		aid, e := admission.Open(ctx, c, key, a, protocol.H([]byte(*batch)))
		if e != nil {
			return e
		}
		fmt.Println(aid)
		return nil
	case "audit-challenge":
		if e := localio.RequireNew(*out); e != nil {
			return e
		}
		a, _, e := loadAdmission()
		if e != nil {
			return e
		}
		privateDir := *stateDir
		if privateDir == "" {
			privateDir = filepath.Join(filepath.Dir(cfg.AccountKey), "audit-state")
		}
		ch, e := admission.CreateChallenge(ctx, c, key, *id, a, privateDir)
		if e != nil {
			return e
		}
		return localio.WriteJSON(*out, ch)
	case "audit-respond":
		a, ch, e := loadAdmission()
		if e != nil {
			return e
		}
		var d protocol.Dataset
		if e = localio.ReadJSON(*dataset, &d); e != nil {
			return e
		}
		response, e := admission.Respond(ctx, c, key, a, ch, d)
		if e != nil {
			return e
		}
		return localio.WriteJSON(*out, response)
	case "audit-decide":
		a, ch, e := loadAdmission()
		if e != nil {
			return e
		}
		var dec decision
		if e = localio.ReadJSON(*in, &dec); e != nil {
			return e
		}
		if dec.Accepted {
			if dec.ReceivedAt == 0 || dec.ReceivedAt > a.Policy.MaterialDeadline || dec.EvidenceReference == "" {
				return errors.New("acceptance requires timely complete materials and recorded manual business decision")
			}
			var response admission.Response
			if e = localio.ReadJSON(*responseFile, &response); e != nil {
				return e
			}
			if e = admission.CheckResponse(ctx, c, a, ch, response); e != nil {
				return e
			}
		}
		_, e = c.Send(ctx, key, nil, "decideAudit", new(big.Int).SetUint64(ch.AID), dec.Accepted)
		if e != nil {
			return e
		}
		record, e := c.Audit(ctx, ch.AID, true)
		if e == nil {
			fmt.Println(record.Did)
		}
		return e
	case "audit-expire":
		_, e = c.Send(ctx, key, nil, "expireAudit", n)
		return e
	case "trade-register", "trade-check", "deposit":
		var a agreement
		if e = localio.ReadJSON(*in, &a); e != nil {
			return e
		}
		price, ok := new(big.Int).SetString(a.Price, 10)
		if !ok || price.Sign() <= 0 {
			return errors.New("positive wei price required")
		}
		if action == "trade-register" {
			if ethcrypto.PubkeyToAddress(key.PublicKey) != a.Owner {
				return errors.New("agreement owner mismatch")
			}
			r, e := c.Send(ctx, key, nil, "registerTrade", new(big.Int).SetUint64(a.DID), [32]byte(a.Source), [32]byte(a.Measurement), a.Buyer, price, a.Duration)
			if e != nil {
				return e
			}
			tid, e := c.EventID(r, "TradeRegistered")
			if e == nil {
				fmt.Println(tid)
			}
			return e
		}
		t, e := c.Trade(ctx, *id, true)
		if e != nil {
			return e
		}
		if t.Did.Cmp(new(big.Int).SetUint64(a.DID)) != 0 || t.Owner != a.Owner || t.Buyer != a.Buyer || t.Source != a.Source || t.Measurement != a.Measurement || t.Price.Cmp(price) != 0 || t.Duration != a.Duration {
			return errors.New("registered terms differ from locally agreed manifest")
		}
		if action == "deposit" {
			_, e = c.Send(ctx, key, price, "deposit", n)
			return e
		}
		fmt.Println("terms and supplied build measurement match")
		return nil
	case "attest":
		w, e := connect(false)
		if e != nil {
			return e
		}
		defer w.Close()
		return json.NewEncoder(os.Stdout).Encode(w.Info)
	case "confirm-key":
		w, e := connect(false)
		if e != nil {
			return e
		}
		defer w.Close()
		_, e = c.Send(ctx, key, nil, "confirmKey", n, w.KeyAddress())
		return e
	case "encrypt-input":
		var d protocol.Dataset
		if e = localio.ReadJSON(*dataset, &d); e != nil {
			return e
		}
		if e = d.Validate(); e != nil {
			return e
		}
		tree, e := protocol.Build(d)
		if e != nil {
			return e
		}
		t, e := c.Trade(ctx, *id, true)
		if e != nil {
			return e
		}
		if t.Owner != ethcrypto.PubkeyToAddress(key.PublicKey) || tree.Commitment() != t.Commitment {
			return errors.New("data/owner mismatch")
		}
		k, e := protocol.NewKey()
		if e != nil {
			return e
		}
		plain, e := json.Marshal(d)
		if e != nil {
			return e
		}
		encrypted, e := protocol.Seal(k, plain, c.Domain(*id).Bytes())
		clear(plain)
		if e != nil {
			return e
		}
		if e = localio.Write(*keyFile, k); e != nil {
			return e
		}
		return localio.Write(*out, encrypted)
	case "db-input":
		w, e := connect(true)
		if e != nil {
			return e
		}
		defer w.Close()
		var p analyzer.Parameters
		if e = localio.ReadJSON(*params, &p); e != nil {
			return e
		}
		if e = analyzer.Validate(p); e != nil {
			return e
		}
		var sk *ecdh.PrivateKey
		b, e := os.ReadFile(*keyFile)
		if errors.Is(e, os.ErrNotExist) {
			sk, e = ecdh.X25519().GenerateKey(rand.Reader)
			if e == nil {
				e = localio.Write(*keyFile, sk.Bytes())
			}
		} else if e == nil {
			sk, e = ecdh.X25519().NewPrivateKey(b)
		}
		if e != nil {
			return e
		}
		inputStart := time.Now()
		e = w.Send(ctx, key, "/db-input", worker.DBInput{Parameters: p, PublicKey: sk.PublicKey().Bytes()}, nil)
		measured["authenticated_input"] = time.Since(inputStart).Nanoseconds()
		return e
	case "do-input":
		w, e := connect(true)
		if e != nil {
			return e
		}
		defer w.Close()
		k, e := os.ReadFile(*keyFile)
		if e != nil {
			return e
		}
		inputStart := time.Now()
		e = w.Send(ctx, key, "/do-input", worker.DOInput{Key: k}, nil)
		measured["authenticated_input"] = time.Since(inputStart).Nanoseconds()
		return e
	case "execute":
		w, e := connect(true)
		if e != nil {
			return e
		}
		defer w.Close()
		var execution worker.Execution
		if e = w.Send(ctx, key, "/execute", struct{}{}, &execution); e != nil {
			return e
		}
		return localio.WriteJSON(*out, execution)
	case "settle":
		var execution worker.Execution
		if e = localio.ReadJSON(*in, &execution); e != nil {
			return e
		}
		_, e = c.Settle(ctx, key, *id, execution.Receipt, *margin)
		return e
	case "decrypt":
		k, e := os.ReadFile(*keyFile)
		if e != nil {
			return e
		}
		encrypted, e := c.Result(ctx, *id)
		if e != nil {
			return e
		}
		plain, e := protocol.DecryptResult(k, encrypted, c.Domain(*id))
		if e != nil {
			return e
		}
		return localio.Write(*out, plain)
	case "refund":
		_, e = c.Send(ctx, key, nil, "timeoutRefund", n)
		return e
	case "withdraw":
		_, e = c.Send(ctx, key, nil, "withdraw")
		return e
	case "inspect":
		t, e := c.Trade(ctx, *id, true)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(t)
	default:
		return fmt.Errorf("unknown command %q", action)
	}
}
