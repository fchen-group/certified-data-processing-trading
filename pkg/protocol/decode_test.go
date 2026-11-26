package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBoundedDatasetAndRootReconstruction(t *testing.T) {
	for n := 1; n <= 257; n++ {
		r := make([][]byte, n)
		for i := range r {
			r[i] = []byte{byte(i), byte(n)}
		}
		d, _ := Prepare(r)
		b, _ := json.Marshal(d)
		decoded, e := DecodeDataset(b, n, 2)
		if e != nil {
			t.Fatal(e)
		}
		tree, _ := Build(d)
		h, e := ReconstructCommitment(decoded)
		if e != nil || h != tree.Commitment() {
			t.Fatalf("different commitment at size %d", n)
		}
		if n > 1 {
			if _, e = DecodeDataset(b, n-1, 2); e == nil {
				t.Fatal("accepted too many records")
			}
		}
		if _, e = DecodeDataset(b, n, 1); e == nil {
			t.Fatal("accepted oversized record")
		}
	}
	for _, b := range []string{`{"records":[],"salts":[]}`, `{"records":null,"salts":[]}`, `{"records":[],"records":[],"salts":[]}`, `{"records":[],"salts":[],"extra":0}`, `{"records":[],"salts":[]} {}`} {
		if _, e := DecodeDataset([]byte(b), 10, 100); e == nil {
			t.Fatalf("accepted malformed data: %s", b)
		}
	}
}

func TestInPlaceDecryption(t *testing.T) {
	k, _ := NewKey()
	plain := bytes.Repeat([]byte("bounded input"), 100)
	sealed, _ := Seal(k, plain, []byte("trade"))
	copyOfCiphertext := bytes.Clone(sealed)
	decoded, e := OpenInPlace(k, sealed, []byte("trade"))
	if e != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("decryption failed", e)
	}
	if &decoded[0] != &sealed[12] {
		t.Fatal("decryption allocated a separate plaintext buffer")
	}
	if _, e = OpenInPlace(k, copyOfCiphertext, []byte("wrong trade")); e == nil {
		t.Fatal("accepted wrong associated data")
	}
}
