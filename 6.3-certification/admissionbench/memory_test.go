package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPeakRSSUnitsAndMissingData(t *testing.T) {
	value, err := parsePeakRSS([]byte("Name:\ttest\nVmHWM:\t2048 kB\nVmRSS:\t1024 kB\n"))
	if err != nil || value != 2*1024*1024 {
		t.Fatalf("incorrect RSS units: %d %v", value, err)
	}
	for _, bad := range []string{"VmRSS: 1024 kB", "VmHWM: -1 kB", "VmHWM: 0 kB", "VmHWM: 99 MB", "VmHWM: 18446744073709551615 kB"} {
		if _, err := parsePeakRSS([]byte(bad)); err == nil {
			t.Fatal("invalid/missing peak accepted:", bad)
		}
	}
}

func TestMemoryProfileRetainsUsableSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "{\"id\":\"%d\",\"features\":[1,2]}\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := measureMemory(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !r.ProofVerified || r.Dimensions != 2 || r.RecordBytes == 0 || r.RetainedHeap == 0 || r.BaselineHeap == 0 || r.HeapIncrement != int64(r.RetainedHeap)-int64(r.BaselineHeap) {
		t.Fatal("missing or inconsistent memory/retention results")
	}
	if runtime.GOOS == "linux" {
		if r.PreparationPeakRSS == nil || r.BaselinePeakRSS == nil || *r.PreparationPeakRSS < *r.BaselinePeakRSS {
			t.Fatal("missing Linux high-water measurement")
		}
	} else if r.PreparationPeakRSS != nil || r.BaselinePeakRSS != nil {
		t.Fatal("fabricated non-Linux RSS")
	}
	if _, err := measureMemory(path, 1001); err == nil {
		t.Fatal("truncated input accepted")
	}
}
