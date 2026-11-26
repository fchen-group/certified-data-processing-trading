package localio

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"certified-data-processing-trading/pkg/protocol"
)

func ReadJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return protocol.StrictJSON(b, v)
}

// New files only: prevents silently replacing keys, salts, receipts or results.
func Write(path string, b []byte) error {
	if path == "" {
		return errors.New("output path required")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	// Publish a complete, fsynced file without replacing an existing record.
	// Hard-linking the temporary file is atomic and fails if path already exists.
	f, e := os.CreateTemp(filepath.Dir(path), ".cdpt-write-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Link(f.Name(), path); e != nil {
		return e
	}
	return Sync(path)
}

// Sync also makes the directory entry durable before a dependent chain action.
func Sync(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

func RequireNew(path string) error {
	if path == "" {
		return errors.New("output path required")
	}
	_, e := os.Lstat(path)
	if e == nil {
		return os.ErrExist
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}
func WriteJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return Write(path, append(b, '\n'))
}
