// admissionbench measures the off-chain B1/B2/B3 cryptographic components.
// It does not perform business review, contact a chain, or measure network RTT.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"time"

	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/protocol"
)

type preparation struct {
	SaltNS     int64 `json:"salt_prepare_ns"`
	SnapshotNS int64 `json:"snapshot_ns"`
}

type auditMeasurement struct {
	Audit              int           `json:"audit"`
	Indices            []uint64      `json:"indices"`
	ChallengeHash      protocol.Hash `json:"challenge_hash"`
	SampleNS           int64         `json:"sample_ns"`
	ChallengeEncodeNS  int64         `json:"challenge_encode_ns"`
	RespondNS          int64         `json:"respond_ns"`
	ResponseEncodeNS   int64         `json:"response_encode_ns"`
	ResponseDecodeNS   int64         `json:"response_decode_ns"`
	VerifyNS           int64         `json:"verify_ns"`
	SampleRecordBytes  int           `json:"sample_record_bytes"`
	SaltBytes          int           `json:"salt_bytes"`
	ProofHashBytes     int           `json:"proof_hash_bytes"`
	ChallengeWireBytes int           `json:"challenge_wire_bytes"`
	ResponseWireBytes  int           `json:"response_wire_bytes"`
	CumulativeDistinct int           `json:"cumulative_distinct_records"`
}

type measurement struct {
	MeasurementSchema string             `json:"measurement_schema"`
	RecordFormat      string             `json:"record_format"`
	Stage             string             `json:"stage"`
	OS                string             `json:"os"`
	Arch              string             `json:"arch"`
	GoVersion         string             `json:"go_version"`
	Procs             int                `json:"gomaxprocs"`
	N                 int                `json:"n"`
	Dimensions        int                `json:"dimensions"`
	Rho               float64            `json:"rho"`
	Epsilon           float64            `json:"epsilon"`
	Budget            int                `json:"challenge_budget"`
	M                 uint64             `json:"m"`
	RecordBytes       int                `json:"record_bytes"`
	EncodedInputSize  int                `json:"encoded_dataset_bytes"`
	CiphertextBytes   int                `json:"input_ciphertext_bytes"`
	Commitment        protocol.Hash      `json:"commitment"`
	Preparation       preparation        `json:"preparation"`
	Audits            []auditMeasurement `json:"audits"`
	Checks            map[string]bool    `json:"checks"`
}

func readRecords(path string, n int) ([][]byte, error) {
	if n <= 0 {
		return nil, errors.New("positive record count required")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	rows := make([][]byte, 0, n)
	for len(rows) < n && scanner.Scan() {
		rows = append(rows, append([]byte(nil), scanner.Bytes()...))
	}
	if e := scanner.Err(); e != nil {
		return nil, e
	}
	if len(rows) != n {
		return nil, errors.New("dataset has fewer records than requested")
	}
	return rows, nil
}

func normalize(rows [][]byte) ([][]byte, int, error) {
	result := make([][]byte, len(rows))
	seen := make(map[string]bool, len(rows))
	dimensions := 0
	for i, raw := range rows {
		var r analyzer.Record
		if e := protocol.StrictJSON(raw, &r); e != nil {
			return nil, 0, e
		}
		if i == 0 {
			dimensions = len(r.Features)
		}
		if r.ID == "" || seen[r.ID] || dimensions == 0 || len(r.Features) != dimensions {
			return nil, 0, errors.New("invalid record ID or feature dimensions")
		}
		seen[r.ID] = true
		for _, x := range r.Features {
			if math.IsNaN(x) || math.IsInf(x, 0) {
				return nil, 0, errors.New("nonfinite feature")
			}
		}
		var e error
		result[i], e = json.Marshal(r)
		if e != nil {
			return nil, 0, e
		}
	}
	return result, dimensions, nil
}

type samplingPolicy struct {
	Rho     float64 `json:"rho"`
	Epsilon float64 `json:"epsilon"`
}

func measure(rows [][]byte, rho, epsilon float64, audits, budget int) (measurement, error) {
	results, e := measureSweep(rows, []samplingPolicy{{rho, epsilon}}, audits, budget)
	if e != nil {
		return measurement{}, e
	}
	return results[0], nil
}

// One independent repetition owns exactly one random salted snapshot. Different
// policies vary only sampling; their shared preparation is not repeated work.
func measureSweep(rows [][]byte, policies []samplingPolicy, audits, budget int) ([]measurement, error) {
	return measureSweepFormat(rows, policies, audits, budget, "work2.score-record.v1")
}

func measureSweepFormat(rows [][]byte, policies []samplingPolicy, audits, budget int, format string) ([]measurement, error) {
	if audits <= 0 || budget <= 0 || len(policies) == 0 || len(policies) > budget/audits {
		return nil, errors.New("challenge count must be within the declared budget")
	}
	for _, p := range policies {
		if _, e := protocol.SampleSize(uint64(len(rows)), p.Rho, p.Epsilon); e != nil {
			return nil, e
		}
	}
	r := measurement{Stage: "offchain-preexperiment", OS: runtime.GOOS, Arch: runtime.GOARCH,
		GoVersion: runtime.Version(), Procs: runtime.GOMAXPROCS(0), N: len(rows), Budget: budget}
	r.MeasurementSchema, r.RecordFormat = "commitment-v2", format
	records := rows
	var e error
	switch format {
	case analyzer.AdultFormat:
		r.Dimensions = 14
		for _, raw := range rows {
			if _, e := analyzer.ParseAdult(raw); e != nil {
				return nil, e
			}
		}
	case "work2.score-record.v1":
		records, r.Dimensions, e = normalize(rows)
		if e != nil {
			return nil, e
		}
	default:
		return nil, errors.New("unsupported record format")
	}
	// Validation and file loading precede timing. The actual commitment path
	// still performs all necessary allocations/copies on the original row bytes.
	for _, record := range records {
		r.RecordBytes += len(record)
	}
	start := time.Now()
	d, e := protocol.Prepare(records)
	r.Preparation.SaltNS = time.Since(start).Nanoseconds()
	if e != nil {
		return nil, e
	}
	start = time.Now()
	snapshot, e := protocol.NewSnapshot(d)
	if e != nil {
		return nil, e
	}
	r.Commitment = snapshot.Commitment()
	r.Preparation.SnapshotNS = time.Since(start).Nanoseconds()
	results := make([]measurement, 0, len(policies))
	for _, p := range policies {
		point, e := measurePrepared(r, snapshot, p, audits)
		if e != nil {
			return nil, e
		}
		results = append(results, point)
	}
	// Untimed cross-checks and input-size accounting, AFTER all timing windows.
	reconstructed, e := protocol.ReconstructCommitment(d)
	if e != nil || reconstructed != r.Commitment {
		return nil, errors.New("execution reconstruction differs from proof tree")
	}
	r.Checks = map[string]bool{"reconstructed_commitment": true}
	r.Checks["all_decoded_samples_verified"] = true
	samples, _ := snapshot.Respond([]uint64{1})
	samples[0].Record[0] ^= 1
	if protocol.VerifySamples(r.Commitment, uint64(len(rows)), []uint64{1}, samples) == nil {
		return nil, errors.New("tampered record accepted")
	}
	r.Checks["tampered_record_rejected"] = true
	plain, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	key, e := protocol.NewKey()
	if e != nil {
		return nil, e
	}
	ciphertext, e := protocol.Seal(key, plain, protocol.Domain{}.Bytes())
	if e != nil {
		return nil, e
	}
	opened, e := protocol.Open(key, ciphertext, protocol.Domain{}.Bytes())
	if e != nil {
		return nil, e
	}
	decoded, e := protocol.DecodeDataset(opened, len(rows), 1<<20)
	if e != nil {
		return nil, e
	}
	for i := range records {
		if !bytes.Equal(records[i], decoded.Records[i]) || d.Salts[i] != decoded.Salts[i] {
			return nil, errors.New("input envelope changed committed bytes")
		}
	}
	r.Checks["dataset_roundtrip_verified"] = true
	for i := range results {
		results[i].EncodedInputSize, results[i].CiphertextBytes = len(plain), len(ciphertext)
		results[i].Checks = r.Checks
	}
	return results, nil
}

func measurePrepared(r measurement, snapshot *protocol.Snapshot, p samplingPolicy, audits int) (measurement, error) {
	r.Rho, r.Epsilon = p.Rho, p.Epsilon
	m, e := protocol.SampleSize(uint64(r.N), p.Rho, p.Epsilon)
	if e != nil {
		return r, e
	}
	r.M = m
	var start time.Time
	seen := make(map[uint64]bool)
	for j := 1; j <= audits; j++ {
		a := auditMeasurement{Audit: j}
		start = time.Now()
		a.Indices, e = protocol.Sample(uint64(r.N), r.M, nil)
		a.SampleNS = time.Since(start).Nanoseconds()
		if e != nil {
			return r, e
		}
		// Model the exact existing JSON envelopes without any network or chain I/O.
		start = time.Now()
		a.ChallengeHash, e = protocol.ChallengeHash(a.Indices)
		if e != nil {
			return r, e
		}
		challengeWire, e := json.Marshal(admission.Challenge{AID: uint64(j), Indices: a.Indices})
		a.ChallengeEncodeNS = time.Since(start).Nanoseconds()
		if e != nil {
			return r, e
		}
		start = time.Now()
		samples, e := snapshot.Respond(a.Indices)
		a.RespondNS = time.Since(start).Nanoseconds()
		if e != nil {
			return r, e
		}
		start = time.Now()
		wire, e := json.Marshal(admission.Response{AID: uint64(j), Samples: samples})
		a.ResponseEncodeNS = time.Since(start).Nanoseconds()
		if e != nil {
			return r, e
		}
		var received admission.Response
		start = time.Now()
		e = protocol.StrictJSON(wire, &received)
		a.ResponseDecodeNS = time.Since(start).Nanoseconds()
		if e != nil {
			return r, e
		}
		start = time.Now()
		if received.AID != uint64(j) {
			return r, errors.New("response application mismatch")
		}
		e = protocol.VerifySamples(r.Commitment, uint64(r.N), a.Indices, received.Samples)
		a.VerifyNS = time.Since(start).Nanoseconds()
		if e != nil {
			return r, e
		}
		a.ChallengeWireBytes, a.ResponseWireBytes = len(challengeWire), len(wire)
		for _, sample := range samples {
			a.SampleRecordBytes += len(sample.Record)
			a.SaltBytes += len(sample.Salt)
			a.ProofHashBytes += len(sample.Proof.Siblings) * 32
			seen[sample.Index] = true
		}
		a.CumulativeDistinct = len(seen)
		r.Audits = append(r.Audits, a)
	}
	return r, nil
}

func run() error {
	input := flag.String("input", "", "record file (format selected explicitly)")
	format := flag.String("format", "work2.score-record.v1", "work2.score-record.v1 or adult.raw.v1")
	n := flag.Int("records", 1000, "prefix record count")
	rho := flag.Float64("rho", .05, "defective fraction threshold")
	epsilon := flag.Float64("epsilon", .0001, "single-audit bound")
	audits := flag.Int("audits", 1, "challenges on one retained snapshot")
	budget := flag.Int("budget", 100, "per-trajectory local challenge budget")
	policiesJSON := flag.String("policies", "", "JSON array of sampling policies sharing one salted snapshot")
	procs := flag.Int("gomaxprocs", 4, "Go execution parallelism")
	profile := flag.String("profile", "time", "time or memory; memory runs separately from timing")
	stage := flag.String("stage", "preexperiment", "preexperiment or formal; metadata only")
	flag.Parse()
	if flag.NArg() != 0 || *procs <= 0 || (*profile != "time" && *profile != "memory") || (*stage != "preexperiment" && *stage != "formal") {
		return errors.New("invalid arguments")
	}
	runtime.GOMAXPROCS(*procs)
	if *profile == "memory" {
		if *policiesJSON != "" || *audits != 1 || *format != "work2.score-record.v1" {
			return errors.New("memory profile measures preparation once, without an audit trajectory")
		}
		r, e := measureMemory(*input, *n)
		if e != nil {
			return e
		}
		r.Stage = "snapshot-memory-" + *stage
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	var rows [][]byte
	var e error
	if *format == analyzer.AdultFormat {
		f, err := os.Open(*input)
		if err != nil {
			return err
		}
		rows, e = analyzer.ReadAdultRows(f, *n)
		f.Close()
	} else {
		rows, e = readRecords(*input, *n)
	}
	if e != nil {
		return e
	}
	if *policiesJSON != "" {
		var policies []samplingPolicy
		if e := protocol.StrictJSON([]byte(*policiesJSON), &policies); e != nil {
			return e
		}
		results, e := measureSweepFormat(rows, policies, *audits, *budget, *format)
		if e != nil {
			return e
		}
		for i := range results {
			results[i].Stage = "offchain-" + *stage
		}
		return json.NewEncoder(os.Stdout).Encode(results)
	}
	results, e := measureSweepFormat(rows, []samplingPolicy{{*rho, *epsilon}}, *audits, *budget, *format)
	if e != nil {
		return e
	}
	results[0].Stage = "offchain-" + *stage
	return json.NewEncoder(os.Stdout).Encode(results[0])
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
