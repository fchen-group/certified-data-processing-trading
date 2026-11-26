package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFixedRecordLoading(t *testing.T) {
	p := filepath.Join(t.TempDir(), "records")
	if err := os.WriteFile(p, []byte("abcd\nefgh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := readRecords(p, 2, 4)
	if err != nil || len(r) != 2 || !bytes.Equal(r[1], []byte("efgh")) {
		t.Fatalf("load: %v", err)
	}
	for _, c := range [][2]int{{0, 4}, {3, 4}, {2, 3}, {2, 0}} {
		if _, err := readRecords(p, c[0], c[1]); err == nil {
			t.Fatalf("accepted invalid dimensions %v", c)
		}
	}
}

func TestMeasurementChecksAndFreshSalts(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 16} {
		rows := make([][]byte, n)
		for i := range rows {
			rows[i] = bytes.Repeat([]byte{byte(i + 1)}, 128)
		}
		a, e := measure(rows)
		if e != nil {
			t.Fatal(e)
		}
		b, e := measure(rows)
		if e != nil {
			t.Fatal(e)
		}
		if a.TotalNS != a.SaltNS+a.SnapshotNS || a.TotalNS <= 0 || a.Commitment == b.Commitment || a.InputHash != b.InputHash {
			t.Fatal("bad timing or snapshot isolation")
		}
		for _, ok := range a.Checks {
			if !ok {
				t.Fatal("check failed")
			}
		}
	}
	if _, e := measure([][]byte{[]byte("x"), []byte("xx")}); e == nil {
		t.Fatal("unequal lengths accepted")
	}
}
