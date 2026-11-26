package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"

	"certified-data-processing-trading/pkg/protocol"
)

// This profile runs in its own fresh process. Explicit GC is never used in the
// time profile. HeapAlloc after GC describes live Go objects, not resident RAM.
type memoryMeasurement struct {
	Stage              string        `json:"stage"`
	OS                 string        `json:"os"`
	Arch               string        `json:"arch"`
	GoVersion          string        `json:"go_version"`
	Procs              int           `json:"gomaxprocs"`
	N                  int           `json:"n"`
	Dimensions         int           `json:"dimensions"`
	RecordBytes        int           `json:"record_bytes"`
	Commitment         protocol.Hash `json:"commitment"`
	BaselineHeap       uint64        `json:"baseline_live_heap_bytes"`
	RetainedHeap       uint64        `json:"retained_live_heap_bytes"`
	HeapIncrement      int64         `json:"retained_heap_increment_bytes"`
	BaselinePeakRSS    *uint64       `json:"baseline_peak_rss_bytes"`
	PreparationPeakRSS *uint64       `json:"preparation_peak_rss_bytes"`
	RSSSource          string        `json:"peak_rss_source"`
	ProofVerified      bool          `json:"retained_snapshot_verified"`
}

func parsePeakRSS(status []byte) (uint64, error) {
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "VmHWM:" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, errors.New("invalid VmHWM units")
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || kb == 0 || kb > math.MaxUint64/1024 {
			return 0, errors.New("invalid VmHWM value")
		}
		return kb * 1024, nil
	}
	return 0, errors.New("VmHWM missing from proc status")
}

func peakRSS() (*uint64, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil, err
	}
	value, err := parsePeakRSS(status)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// Keep temporary input references in this completed frame so the retention
// checkpoint keeps only the snapshot, not the source rows or Dataset as well.
//
//go:noinline
func prepareMemorySnapshot(path string, n int) (*protocol.Snapshot, int, int, error) {
	rows, err := readRecords(path, n)
	if err != nil {
		return nil, 0, 0, err
	}
	records, dimensions, err := normalize(rows)
	if err != nil {
		return nil, 0, 0, err
	}
	size := 0
	for _, record := range records {
		size += len(record)
	}
	d, err := protocol.Prepare(records)
	if err != nil {
		return nil, 0, 0, err
	}
	snapshot, err := protocol.NewSnapshot(d)
	return snapshot, dimensions, size, err
}

func measureMemory(path string, n int) (memoryMeasurement, error) {
	r := memoryMeasurement{Stage: "snapshot-memory-preexperiment", OS: runtime.GOOS, Arch: runtime.GOARCH,
		GoVersion: runtime.Version(), Procs: runtime.GOMAXPROCS(0), N: n, RSSSource: "unavailable on this OS"}
	if runtime.GOOS == "linux" {
		r.RSSSource = "/proc/self/status:VmHWM; kernel process high-water RSS through preparation"
	}
	var err error
	runtime.GC()
	var before, retained runtime.MemStats
	runtime.ReadMemStats(&before)
	r.BaselineHeap = before.HeapAlloc
	r.BaselinePeakRSS, err = peakRSS()
	if err != nil {
		return r, err
	}
	snapshot, dimensions, size, err := prepareMemorySnapshot(path, n)
	if err != nil {
		return r, err
	}
	// Capture before retention GC and proof verification. This high-water value
	// includes startup, input loading, normalization, salting and tree building;
	// it is NOT a peak attributable only to the tree or a sampled Go heap peak.
	r.PreparationPeakRSS, err = peakRSS()
	if err != nil {
		return r, err
	}
	runtime.GC()
	runtime.ReadMemStats(&retained)
	r.RetainedHeap = retained.HeapAlloc
	r.HeapIncrement = int64(r.RetainedHeap) - int64(r.BaselineHeap)
	r.Dimensions, r.RecordBytes, r.Commitment = dimensions, size, snapshot.Commitment()
	indices := []uint64{1}
	if n > 1 {
		indices = append(indices, uint64(n))
	}
	samples, err := snapshot.Respond(indices)
	if err == nil {
		err = protocol.VerifySamples(r.Commitment, uint64(n), indices, samples)
	}
	runtime.KeepAlive(snapshot)
	if err != nil {
		return r, fmt.Errorf("retained snapshot validation: %w", err)
	}
	r.ProofVerified = true
	return r, nil
}
