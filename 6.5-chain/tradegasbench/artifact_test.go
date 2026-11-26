package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func TestArtifactRuntimeBinding(t *testing.T) {
	auditor := common.HexToAddress("0x1234")
	template := make([]byte, 64)
	template[0] = 0x60
	artifact := func(start, length int) []byte {
		b, _ := json.Marshal(map[string]any{"deployedBytecode": map[string]any{
			"object":              hexutil.Bytes(template),
			"immutableReferences": map[string]any{"75": []map[string]int{{"start": start, "length": length}}},
		}})
		return b
	}
	want := bytes.Clone(template)
	copy(want[1:33], common.LeftPadBytes(auditor.Bytes(), 32))
	h, err := artifactCodeHash(artifact(1, 32), auditor)
	if err != nil || h != ethcrypto.Keccak256Hash(want) {
		t.Fatalf("runtime reconstruction: %s %v", h, err)
	}
	other, err := artifactCodeHash(artifact(1, 32), common.HexToAddress("0x5678"))
	if err != nil || other == h {
		t.Fatal("auditor identity was not bound")
	}
	template[63] = 1
	changed, err := artifactCodeHash(artifact(1, 32), auditor)
	if err != nil || changed == h {
		t.Fatal("runtime change was not detected")
	}
	for _, offset := range [][2]int{{-1, 32}, {40, 32}, {1, 20}} {
		if _, err := artifactCodeHash(artifact(offset[0], offset[1]), auditor); err == nil {
			t.Fatal("invalid immutable offset accepted", offset)
		}
	}
}
