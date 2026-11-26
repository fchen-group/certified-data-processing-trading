package worker

import (
	"errors"
	"io"
	"os"
)

// Compiled prototype limits, paired with the 1024 MiB signing configuration.
// Raising these requires rebuilding and repeating the resource regression.
const MaxCiphertextBytes int64 = 32 << 20
const MaxRecords = 100000
const MaxRecordBytes = 1 << 20
const GoMemoryTarget int64 = 768 << 20

// ReadInput rejects oversized regular files before allocating their contents.
// The untrusted file may change after Stat, so check both short reads and growth.
func ReadInput(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > MaxCiphertextBytes {
		return nil, errors.New("input limit exceeds compiled prototype policy")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, errors.New("input is not a regular file within size cap")
	}
	b := make([]byte, int(info.Size()))
	if _, e = io.ReadFull(f, b); e != nil {
		return nil, e
	}
	var extra [1]byte
	n, e := f.Read(extra[:])
	if n != 0 || e != io.EOF {
		return nil, errors.New("input changed while reading")
	}
	return b, nil
}
