package worker

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/protocol"
)

func TestInputByteLimitBeforeAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ciphertext")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(MaxCiphertextBytes + 1); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e = ReadInput(path, MaxCiphertextBytes); e == nil {
		t.Fatal("accepted oversized file")
	}
	if _, e = ReadInput(path, MaxCiphertextBytes+1); e == nil {
		t.Fatal("host raised compiled cap")
	}
	if e = os.WriteFile(path, []byte("small"), 0600); e != nil {
		t.Fatal(e)
	}
	b, e := ReadInput(path, 5)
	if e != nil || string(b) != "small" {
		t.Fatal("valid boundary rejected", e)
	}
	if _, e = ReadInput(path, 4); e == nil {
		t.Fatal("lower local limit not enforced")
	}
}

// Runs only on request. Each scenario uses a fresh process so preparation by
// DO and previous test allocations cannot be mistaken for enclave memory use.
func TestResourceEnvelope(t *testing.T) {
	if path := os.Getenv("WORK2_RESOURCE_INPUT"); path != "" {
		runResourceChild(t, path)
		return
	}
	if os.Getenv("WORK2_RESOURCE_TEST") != "1" {
		t.Skip("set WORK2_RESOURCE_TEST=1 for native resource regression")
	}
	for _, tc := range []struct {
		name         string
		count, width int
		full         bool
	}{
		{"small", 8, 16, false}, {"max-records", MaxRecords, 16, false}, {"max-bytes-wide-records", 32, 700000, true},
		{"max-bytes-and-records", MaxRecords, 128, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := make([][]byte, tc.count)
			for i := range records {
				records[i], _ = json.Marshal(analyzer.Record{ID: strconv.Itoa(i) + strings.Repeat("x", tc.width), Features: []float64{1}})
			}
			d, e := protocol.Prepare(records)
			if e != nil {
				t.Fatal(e)
			}
			plain, _ := json.Marshal(d)
			if tc.full {
				padding := int(MaxCiphertextBytes) - 28 - len(plain)
				if padding < 0 {
					t.Fatal("fixture exceeds cap")
				}
				plain = append(plain, bytes.Repeat([]byte(" "), padding)...)
			}
			ciphertext, e := protocol.Seal(bytes.Repeat([]byte{1}, 32), plain, resourceDomain().Bytes())
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "input.bin")
			if e = os.WriteFile(path, ciphertext, 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestResourceEnvelope$", "-test.v")
			cmd.Env = append(os.Environ(), "WORK2_RESOURCE_INPUT="+path, "WORK2_RESOURCE_COUNT="+strconv.Itoa(tc.count))
			output, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("resource child: %s: %v", output, e)
			}
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, "RESOURCE ") {
					t.Log(line)
				}
			}
		})
	}
}

func resourceDomain() protocol.Domain {
	return protocol.Domain{ChainID: 31337, Contract: common.HexToAddress("0x1234"), TID: 1}
}

func runResourceChild(t *testing.T, path string) {
	debug.SetMemoryLimit(GoMemoryTarget)
	runtime.GOMAXPROCS(4)
	key, _ := ethcrypto.GenerateKey()
	sk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	s := &Server{domain: resourceDomain(), key: key, input: func() ([]byte, error) { return ReadInput(path, MaxCiphertextBytes) },
		do: &DOInput{Key: bytes.Repeat([]byte{1}, 32)}, db: &DBInput{Parameters: analyzer.Parameters{Weights: []float64{1}}, PublicKey: sk.PublicKey().Bytes()}}
	runtime.GC()
	type memory struct{ Alloc, Inuse, Sys uint64 }
	done, measured := make(chan struct{}), make(chan memory)
	go func() {
		var peak memory
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		read := func() {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			peak.Alloc = max(peak.Alloc, m.HeapAlloc)
			peak.Inuse = max(peak.Inuse, m.HeapInuse)
			peak.Sys = max(peak.Sys, m.Sys)
		}
		for {
			select {
			case <-ticker.C:
				read()
			case <-done:
				read()
				measured <- peak
				return
			}
		}
	}()
	out, e := s.execute()
	close(done)
	peak := <-measured
	if e != nil {
		t.Fatal(e)
	}
	if e = protocol.VerifyReceipt(resourceDomain(), out.Receipt, ethcrypto.PubkeyToAddress(key.PublicKey)); e != nil {
		t.Fatal(e)
	}
	plaintext, e := protocol.DecryptResult(sk.Bytes(), out.Receipt.Ciphertext, resourceDomain())
	if e != nil {
		t.Fatal(e)
	}
	count, _ := strconv.Atoi(os.Getenv("WORK2_RESOURCE_COUNT"))
	expected, _ := json.Marshal(analyzer.Result{Count: uint64(count), Above: uint64(count)})
	if !bytes.Equal(plaintext, expected) {
		t.Fatalf("wrong result %s", plaintext)
	}
	if peak.Inuse >= uint64(GoMemoryTarget) || peak.Sys >= 1<<30 {
		t.Fatalf("exceeded resource budget: %+v", peak)
	}
	info, _ := os.Stat(path)
	row, _ := json.Marshal(map[string]any{"mode": "native", "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "input_bytes": info.Size(), "records": count, "configured_enclave_heap_mib": 1024, "go_memory_target_mib": 768, "peak_heap_alloc_bytes": peak.Alloc, "peak_heap_inuse_bytes": peak.Inuse, "peak_go_sys_bytes": peak.Sys, "sampling_interval_ms": 1})
	fmt.Println("RESOURCE " + string(row))
}
