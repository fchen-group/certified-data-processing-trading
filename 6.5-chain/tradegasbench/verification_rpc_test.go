package main

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/protocol"
)

func TestVerificationRPCPreservesMeasuredIdentity(t *testing.T) {
	r := record{Chain: chain.Config{RPC: "https://old.example", ChainID: 11155111,
		Contract: common.HexToAddress("0x1234"), CodeHash: common.HexToHash("0x5678")}}
	before := r.Chain
	v := verificationRPC{"https://archive.example", strings.Repeat("ab", 32), "https://independent.example"}
	if err := v.apply(&r); err != nil {
		t.Fatal(err)
	}
	if r.Chain.ChainID != before.ChainID || r.Chain.Contract != before.Contract || r.Chain.CodeHash != before.CodeHash || r.Chain.Development != before.Development {
		t.Fatal("changed measured identity")
	}
	if r.Chain.RPC != v.RPC || r.Chain.RPCSPKI != v.RPCSPKI || r.SecondaryRPC != v.SecondaryRPC {
		t.Fatal("endpoints not updated")
	}
}

func TestVerificationRPCRejectsUnsafeOverrides(t *testing.T) {
	valid := verificationRPC{"https://archive.example", strings.Repeat("ab", 32), "https://independent.example"}
	for _, mutate := range []func(*verificationRPC){
		func(v *verificationRPC) { v.RPC = "http://archive.example" },
		func(v *verificationRPC) { v.RPCSPKI = "abcd" },
		func(v *verificationRPC) { v.SecondaryRPC = "https://archive.example/other" },
		func(v *verificationRPC) { v.SecondaryRPC = "http://independent.example" },
	} {
		v := valid
		mutate(&v)
		r := record{Chain: chain.Config{RPC: "https://original.example"}}
		if err := v.apply(&r); err == nil || r.Chain.RPC != "https://original.example" {
			t.Fatal("accepted invalid override or partially mutated record")
		}
	}
	var v verificationRPC
	if err := protocol.StrictJSON([]byte(`{"rpc":"https://archive.example","chain_id":1}`), &v); err == nil {
		t.Fatal("accepted chain identity override")
	}
}

func TestVerificationConfigOnlyAllowedReadonly(t *testing.T) {
	err := run([]string{"-out", "out", "-state-dir", "private", "-timeout", "1s", "-verification-config", "override.json"})
	if err == nil || !strings.Contains(err.Error(), "requires verify-only") {
		t.Fatalf("wrong flag validation: %v", err)
	}
}
