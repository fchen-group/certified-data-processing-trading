package chain

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Sepolia block 12019016 (2026-10-29) contains the Amsterdam BAL header
// field. Older dependencies silently discard it and compute the wrong hash,
// causing Wait's canonical-block check to never succeed after finalization.
func TestSepoliaAmsterdamHeaderHash(t *testing.T) {
	raw, err := os.ReadFile("testdata/sepolia-amsterdam-header.json")
	if err != nil {
		t.Fatal(err)
	}
	var header types.Header
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	want := common.HexToHash("0x8216487039878e02b28509051e6ebe7b60f34e01342f19562b44d793e85460c7")
	if got := header.Hash(); got != want {
		t.Fatalf("canonical header hash = %s, want %s; check fork compatibility", got, want)
	}
}
