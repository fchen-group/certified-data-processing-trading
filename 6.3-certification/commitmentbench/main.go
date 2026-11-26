// commitmentbench measures the same Prepare/NewSnapshot interval as admissionbench,
// using fixed-length raw records. Input loading and all checks are outside timing.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"certified-data-processing-trading/pkg/protocol"
)

type result struct {
	Schema      string                  `json:"schema"`
	OS          string                  `json:"os"`
	Arch        string                  `json:"arch"`
	Go          string                  `json:"go_version"`
	Procs       int                     `json:"gomaxprocs"`
	N           int                     `json:"n"`
	Length      int                     `json:"record_length"`
	RecordBytes int                     `json:"record_bytes"`
	InputHash   string                  `json:"record_sha256"`
	SaltNS      int64                   `json:"salt_prepare_ns"`
	SnapshotNS  int64                   `json:"snapshot_ns"`
	TotalNS     int64                   `json:"preparation_ns"`
	Commitment  protocol.Hash           `json:"commitment"`
	Indices     []uint64                `json:"indices"`
	Samples     []protocol.SampleRecord `json:"samples"`
	Checks      map[string]bool         `json:"checks"`
}

func readRecords(path string, n, length int) ([][]byte, error) {
	if n < 1 || length < 1 || length > 1<<20 {
		return nil, errors.New("invalid record count or length")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), (1<<20)+2)
	rows := make([][]byte, 0, n)
	for len(rows) < n && s.Scan() {
		if len(s.Bytes()) != length {
			return nil, errors.New("unexpected record length")
		}
		rows = append(rows, append([]byte(nil), s.Bytes()...))
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(rows) != n {
		return nil, errors.New("insufficient records")
	}
	return rows, nil
}

func measure(rows [][]byte) (result, error) {
	if len(rows) == 0 || len(rows[0]) == 0 {
		return result{}, errors.New("empty input")
	}
	r := result{Schema: "commitment-length-v1", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Go: runtime.Version(), Procs: runtime.GOMAXPROCS(0), N: len(rows), Length: len(rows[0])}
	for _, row := range rows {
		if len(row) != r.Length {
			return result{}, errors.New("unequal record lengths")
		}
		r.RecordBytes += len(row)
	}
	// Identical operation order and clock boundaries to admissionbench's preparation.
	start := time.Now()
	d, err := protocol.Prepare(rows)
	r.SaltNS = time.Since(start).Nanoseconds()
	if err != nil {
		return r, err
	}
	start = time.Now()
	snapshot, err := protocol.NewSnapshot(d)
	if err != nil {
		return r, err
	}
	r.Commitment = snapshot.Commitment()
	r.SnapshotNS = time.Since(start).Nanoseconds()
	r.TotalNS = r.SaltNS + r.SnapshotNS

	// Checks below do not contribute to the reported construction time.
	h := sha256.New()
	for _, row := range rows {
		h.Write(row)
	}
	r.InputHash = hex.EncodeToString(h.Sum(nil))
	c, err := protocol.ReconstructCommitment(d)
	if err != nil || c != r.Commitment {
		return r, errors.New("reconstruction mismatch")
	}
	r.Indices = []uint64{1}
	if r.N > 2 {
		r.Indices = append(r.Indices, uint64(r.N/2+1))
	}
	if r.N > 1 {
		r.Indices = append(r.Indices, uint64(r.N))
	}
	r.Samples, err = snapshot.Respond(r.Indices)
	if err != nil {
		return r, err
	}
	if err = protocol.VerifySamples(r.Commitment, uint64(r.N), r.Indices, r.Samples); err != nil {
		return r, err
	}
	bad, err := snapshot.Respond(r.Indices)
	if err != nil {
		return r, err
	}
	bad[0].Record[0] ^= 1
	if protocol.VerifySamples(r.Commitment, uint64(r.N), r.Indices, bad) == nil {
		return r, errors.New("tampered record accepted")
	}
	r.Checks = map[string]bool{"reconstructed_commitment": true, "proofs_verified": true, "tampered_record_rejected": true}
	return r, nil
}

func main() {
	path := flag.String("input", "", "newline-separated fixed-length records")
	n := flag.Int("n", 0, "prefix record count")
	length := flag.Int("length", 0, "raw bytes per record, excluding newline and salt")
	flag.Parse()
	rows, err := readRecords(*path, *n, *length)
	if err == nil {
		var r result
		r, err = measure(rows)
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(r)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
