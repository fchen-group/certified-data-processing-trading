package localio

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAtomicCreateNeverOverwritesOrPublishesPartialData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate.json")
	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if WriteJSON(path, map[string]int{"value": 42}) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful creates: %d", successes.Load())
	}
	var value map[string]int
	if e := ReadJSON(path, &value); e != nil || value["value"] != 42 {
		t.Fatal("incomplete durable record", e)
	}
	if e := Write(path, []byte("overwrite")); e == nil {
		t.Fatal("overwrote candidate")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatal("temporary files left behind")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe file permissions")
	}
}
