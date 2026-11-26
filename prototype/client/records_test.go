package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"certified-data-processing-trading/pkg/analyzer"
)

func TestPrepareLoadsCompleteAdultRecord(t *testing.T) {
	row := []byte("39, ?, 77516, Bachelors, 13, Never-married, Adm-clerical, Not-in-family, White, Male, 2174, 0, 40, United-States, <=50K. ")
	path := filepath.Join(t.TempDir(), "adult.csv")
	if err := os.WriteFile(path, append(append([]byte("|header\r\n"), row...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := loadInputRecords(path, analyzer.AdultFormat)
	if err != nil || len(rows) != 1 || !bytes.Equal(rows[0], row) {
		t.Fatal("prepare rewrote the record", err)
	}
	if _, err := loadInputRecords(path, "unknown"); err == nil {
		t.Fatal("unknown format accepted")
	}
}
