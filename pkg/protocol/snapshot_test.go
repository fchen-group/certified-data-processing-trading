package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

func TestSnapshotRetainsExactDatasetAcrossChallenges(t *testing.T) {
	d := data(23)
	want, _ := ReconstructCommitment(d)
	s, e := NewSnapshot(d)
	if e != nil {
		t.Fatal(e)
	}
	// The owner may reuse or overwrite its source buffers after construction.
	d.Records[0][0] ^= 1
	d.Salts[0][0] ^= 1
	d.Records[22] = []byte("changed")
	for _, indices := range [][]uint64{{1, 12, 23}, {2, 8}, {1, 23}} {
		got, e := s.Respond(indices)
		if e != nil || s.Commitment() != want || s.Count() != 23 {
			t.Fatalf("snapshot changed: %v", e)
		}
		if e := VerifySamples(want, 23, indices, got); e != nil {
			t.Fatal(e)
		}
		legacy, e := Respond(data(23), indices)
		if e != nil || !reflect.DeepEqual(got, legacy) {
			t.Fatal("proof/wire semantics changed")
		}
		// A consumer must not mutate the retained snapshot or future responses.
		got[0].Record[0] ^= 1
		got[0].Salt[0] ^= 1
		got[0].Proof.Siblings[0][0] ^= 1
	}
	got, _ := s.Respond([]uint64{1})
	if !bytes.Equal(got[0].Record, data(23).Records[0]) {
		t.Fatal("returned record aliased snapshot")
	}
}

func TestSnapshotRejectsInvalidStateAndChallenges(t *testing.T) {
	if _, e := NewSnapshot(Dataset{}); e == nil {
		t.Fatal("empty dataset accepted")
	}
	for _, s := range []*Snapshot{nil, {}} {
		if _, e := s.Respond([]uint64{1}); e == nil {
			t.Fatal("empty snapshot accepted")
		}
	}
	s, _ := NewSnapshot(data(1))
	for _, indices := range [][]uint64{nil, {0}, {2}, {1, 1}, {2, 1}} {
		if _, e := s.Respond(indices); e == nil {
			t.Fatalf("invalid challenge accepted: %v", indices)
		}
	}
	got, e := s.Respond([]uint64{1})
	if e != nil || VerifySamples(s.Commitment(), 1, []uint64{1}, got) != nil {
		t.Fatal("singleton snapshot failed")
	}
}
