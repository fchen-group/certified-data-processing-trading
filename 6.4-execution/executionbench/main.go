// executionbench is an isolated compute microbenchmark for PUBLIC fixtures.
// It is not a protocol server: fixture keys are host-readable test values.
// No deployment, ledger, identity-check or attestation claim is made here.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/perfclock"
	"certified-data-processing-trading/pkg/platform"
	"certified-data-processing-trading/pkg/protocol"
	"certified-data-processing-trading/pkg/worker"
)

type fixture struct {
	Purpose       string              `json:"purpose"`
	Domain        protocol.Domain     `json:"domain"`
	N             int                 `json:"n"`
	Key           []byte              `json:"key"`
	ResultKey     []byte              `json:"result_key"`
	Parameters    analyzer.Parameters `json:"parameters"`
	Commitment    protocol.Hash       `json:"commitment"`
	CipherSHA256  string              `json:"cipher_sha256"`
	RecordsSHA256 string              `json:"records_sha256"`
	Expected      json.RawMessage     `json:"expected"`
}

const purpose = "public-fixture-compute-only-v1"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "run", "prepare or run (public test fixtures only)")
	dir := flag.String("fixture", "", "new fixture directory for prepare; existing directory for run")
	input := flag.String("input", "", "raw Adult records for preparation")
	params := flag.String("parameters", "", "model parameter JSON; empty selects T1")
	expected := flag.String("expected", "", "independent reference result JSON for preparation")
	n := flag.Int("n", 0, "number of records for preparation")
	diagnostic := flag.Bool("diagnostic", false, "diagnostic observations, never formal measurements")
	preGC := flag.Bool("pre-gc", true, "collect setup allocations before computation (diagnostic override only)")
	iterations := flag.Int("iterations", 1, "computations in one process (diagnostic only)")
	settle := flag.Duration("settle", 0, "diagnostic delay after setup collection")
	flag.Parse()
	if *iterations < 1 || *iterations > 3 || *settle < 0 || *settle > time.Second || (!*diagnostic && (!*preGC || *iterations != 1 || *settle != 0)) {
		return errors.New("nonstandard execution conditions require diagnostic mode")
	}
	if *dir == "" {
		return errors.New("fixture directory required")
	}
	debug.SetMemoryLimit(worker.GoMemoryTarget)
	switch *mode {
	case "prepare":
		if platform.HardwareBuild {
			return errors.New("prepare fixtures outside SGX")
		}
		return prepare(*dir, *input, *params, *expected, *n)
	case "run":
		return measureWithOptions(*dir, *diagnostic, *preGC, *iterations, *settle)
	default:
		return errors.New("unknown benchmark mode")
	}
}

func prepare(dir, input, params, expected string, n int) error {
	if n <= 0 || n > worker.MaxRecords || expected == "" {
		return errors.New("valid n and independent expected result required")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		return errors.New("fixture output must not exist")
	}
	file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer file.Close()
	rows, err := analyzer.ReadAdultRows(file, n)
	if err != nil {
		return err
	}
	p := analyzer.Parameters{Task: analyzer.AdultStatistics}
	if params != "" {
		if err = localio.ReadJSON(params, &p); err != nil {
			return err
		}
	}
	if err = analyzer.Validate(p); err != nil {
		return err
	}
	reference, err := os.ReadFile(expected)
	if err != nil {
		return err
	}
	// This is a validation, not the measured execution. It catches wrong task,
	// reference or subset choices before a fixture is used for measurements.
	actual, err := analyzer.Analyze(rows, p)
	if err != nil {
		return err
	}
	if err = compareResult(p.Task, actual, reference, n); err != nil {
		return err
	}
	d, err := protocol.Prepare(rows)
	if err != nil {
		return err
	}
	tree, err := protocol.Build(d)
	if err != nil {
		return err
	}
	k, err := protocol.NewKey()
	if err != nil {
		return err
	}
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	domain := protocol.Domain{ChainID: 31337, Contract: common.HexToAddress("0x1234"), TID: 1}
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	ciphertext, err := protocol.Seal(k, raw, domain.Bytes())
	if err != nil {
		return err
	}
	if int64(len(ciphertext)) > worker.MaxCiphertextBytes {
		return errors.New("fixture exceeds compiled input limit")
	}
	h := sha256.New()
	for _, row := range rows {
		h.Write(row)
		h.Write([]byte{'\n'})
	}
	f := fixture{purpose, domain, n, k, sk.Bytes(), p, tree.Commitment(),
		sha(ciphertext), hex.EncodeToString(h.Sum(nil)), reference}
	if err = localio.Write(filepath.Join(dir, "input.bin"), ciphertext); err != nil {
		return err
	}
	return localio.WriteJSON(filepath.Join(dir, "fixture.json"), f)
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func measure(dir string) error {
	return measureWithOptions(dir, false, true, 1, 0)
}

func gcCycles() uint64 {
	s := []metrics.Sample{{Name: "/gc/cycles/total:gc-cycles"}}
	metrics.Read(s)
	return s[0].Value.Uint64()
}

func measureWithOptions(dir string, diagnostic, preGC bool, iterations int, settle time.Duration) error {
	meta, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		return err
	}
	var f fixture
	if err = protocol.StrictJSON(meta, &f); err != nil {
		return err
	}
	if f.Purpose != purpose || f.N <= 0 || f.N > worker.MaxRecords {
		return errors.New("invalid public fixture")
	}
	if err = analyzer.Validate(f.Parameters); err != nil {
		return err
	}
	input := filepath.Join(dir, "input.bin")
	file, err := os.Open(input)
	if err != nil {
		return err
	}
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(file, worker.MaxCiphertextBytes+1))
	file.Close()
	if err != nil {
		return err
	}
	if size > worker.MaxCiphertextBytes || hex.EncodeToString(h.Sum(nil)) != f.CipherSHA256 {
		return errors.New("ciphertext checksum mismatch")
	}
	// Hash validation also primes the host page cache. There is one fresh
	// computation per process. Setup allocations are collected before timing;
	// GC caused by the computation remains inside the measured interval.
	sk, err := ecdh.X25519().NewPrivateKey(f.ResultKey)
	if err != nil {
		return err
	}
	signer, err := ethcrypto.GenerateKey()
	if err != nil {
		return err
	}
	if preGC {
		runtime.GC()
	}
	if settle > 0 {
		time.Sleep(settle)
	}
	for iteration := 1; iteration <= iterations; iteration++ {
		var before uint64
		if diagnostic {
			before = gcCycles()
		}
		out, err := worker.Compute(f.Domain, signer, func() ([]byte, error) {
			return worker.ReadInput(input, worker.MaxCiphertextBytes)
		}, worker.DOInput{Key: f.Key}, worker.DBInput{Parameters: f.Parameters, PublicKey: sk.PublicKey().Bytes()})
		if err != nil {
			return err
		}
		var collections uint64
		if diagnostic {
			collections = gcCycles() - before
		}
		if out.Receipt.Commitment != f.Commitment {
			return errors.New("computed commitment mismatch")
		}
		if err = protocol.VerifyReceipt(f.Domain, out.Receipt, ethcrypto.PubkeyToAddress(signer.PublicKey)); err != nil {
			return err
		}
		result, err := protocol.DecryptResult(f.ResultKey, out.Receipt.Ciphertext, f.Domain)
		if err != nil {
			return err
		}
		if err = compareResult(f.Parameters.Task, result, f.Expected, f.N); err != nil {
			return err
		}
		var sum int64
		for _, name := range []string{"load_ciphertext", "decrypt_parse", "commitment", "analyze", "encrypt_sign"} {
			v, ok := out.Nanoseconds[name]
			if !ok || v <= 0 {
				return fmt.Errorf("missing/invalid phase timing: %s=%d ns (present=%t); phases=%v total=%d ns", name, v, ok, out.Nanoseconds, out.TotalNanoseconds)
			}
			sum += v
		}
		if sum > out.TotalNanoseconds {
			return errors.New("phase timings exceed total")
		}
		backend := "native"
		if platform.HardwareBuild {
			backend = "sgx-build"
		}
		point := map[string]any{
			"schema": purpose, "backend": backend, "task": f.Parameters.Task, "n": f.N,
			"go": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0), "memory_limit": worker.GoMemoryTarget,
			"clock":          perfclock.Source,
			"fixture_sha256": sha(meta), "ciphertext_bytes": size, "records_sha256": f.RecordsSHA256,
			"total_ns": out.TotalNanoseconds, "phases_ns": out.Nanoseconds,
			"result": json.RawMessage(result), "validated": true,
		}
		if diagnostic {
			point["diagnostic"] = true
			point["iteration"] = iteration
			point["pre_gc"] = preGC
			point["settle_ns"] = int64(settle)
			point["compute_gc_cycles"] = collections
		}
		if err = json.NewEncoder(os.Stdout).Encode(point); err != nil {
			return err
		}
	}
	return nil
}

func compareResult(task string, actual, expected []byte, n int) error {
	if task == analyzer.AdultIncome {
		var a, b analyzer.Result
		if protocol.StrictJSON(actual, &a) != nil || protocol.StrictJSON(expected, &b) != nil || a != b || a.Count != uint64(n) {
			return errors.New("classification reference mismatch")
		}
		return nil
	}
	if task != analyzer.AdultStatistics {
		return errors.New("unsupported benchmark task")
	}
	var a, b analyzer.StatisticsResult
	if protocol.StrictJSON(actual, &a) != nil || protocol.StrictJSON(expected, &b) != nil || a.Count != b.Count || a.Count != uint64(n) {
		return errors.New("statistics reference count mismatch")
	}
	xs := []float64{a.Age.Mean, a.Age.PopulationVariance, a.HoursPerWeek.Mean, a.HoursPerWeek.PopulationVariance}
	ys := []float64{b.Age.Mean, b.Age.PopulationVariance, b.HoursPerWeek.Mean, b.HoursPerWeek.PopulationVariance}
	for i, x := range xs {
		if math.IsNaN(x) || math.IsInf(x, 0) || math.IsNaN(ys[i]) || math.IsInf(ys[i], 0) || math.Abs(x-ys[i]) > 1e-9*(1+math.Abs(ys[i])) {
			return errors.New("statistics reference value mismatch")
		}
	}
	return nil
}
