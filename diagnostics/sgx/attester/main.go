//go:build ego

// This diagnostic emits only public test data and an SGX report.
package main

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/edgelesssys/ego/enclave"
)

func main() {
	nonceHex := flag.String("nonce", "", "32-byte verifier challenge, hex encoded")
	flag.Parse()
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil || len(nonce) != 32 {
		fmt.Fprintln(os.Stderr, "expected a 32-byte challenge")
		os.Exit(1)
	}
	var result uint64
	for i := uint64(1); i <= 1000; i++ {
		result += i
	}
	message := append([]byte("work2-sgx-smoke-v1\x00"), nonce...)
	message = binary.BigEndian.AppendUint64(message, result)
	data := sha512.Sum512(message)
	report, err := enclave.GetRemoteReport(data[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetRemoteReport:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Report []byte `json:"report"`
		Result uint64 `json:"result"`
	}{report, result}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
