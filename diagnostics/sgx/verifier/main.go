//go:build dcap

// This native process verifies a real DCAP report without accepting stale TCBs.
package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/eclient"
)

func verify(raw, measurement, data []byte) (attestation.Report, error) {
	r, err := eclient.VerifyRemoteReport(raw)
	if err != nil {
		return r, err
	}
	if r.Debug || r.SecurityVersion != 1 || !bytes.Equal(r.UniqueID, measurement) || !bytes.Equal(r.Data, data) {
		return r, errors.New("debug, security version, measurement or challenge/result binding mismatch")
	}
	return r, nil
}

func run() error {
	path := flag.String("report", "", "public report JSON")
	idHex := flag.String("measurement", "", "expected MRENCLAVE from the signed build")
	nonceHex := flag.String("nonce", "", "original verifier challenge")
	flag.Parse()
	id, err := hex.DecodeString(*idHex)
	if err != nil || len(id) != 32 {
		return errors.New("expected a 32-byte measurement")
	}
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil || len(nonce) != 32 {
		return errors.New("expected a 32-byte challenge")
	}
	input, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var payload struct {
		Report []byte `json:"report"`
		Result uint64 `json:"result"`
	}
	if err := json.Unmarshal(input, &payload); err != nil {
		return err
	}
	if payload.Result != 1000*1001/2 {
		return errors.New("incorrect calculation result")
	}
	message := append([]byte("work2-sgx-smoke-v1\x00"), nonce...)
	message = binary.BigEndian.AppendUint64(message, payload.Result)
	data := sha512.Sum512(message)
	r, err := verify(payload.Report, id, data[:])
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"accepted": false, "error": err.Error(), "tcb_status": r.TCBStatus.String(),
			"tcb_advisories": r.TCBAdvisories, "debug": r.Debug,
		})
		return fmt.Errorf("strict DCAP verification: %w", err)
	}
	wrongID := bytes.Clone(id)
	wrongID[0] ^= 1
	if _, err := verify(payload.Report, wrongID, data[:]); err == nil {
		return errors.New("incorrect measurement was accepted")
	}
	wrongData := data
	wrongData[0] ^= 1
	if _, err := verify(payload.Report, id, wrongData[:]); err == nil {
		return errors.New("incorrect report data was accepted")
	}
	corrupt := bytes.Clone(payload.Report)
	if len(corrupt) < 512 {
		return errors.New("unexpectedly short SGX report")
	}
	corrupt[len(corrupt)/3] ^= 1
	if _, err := verify(corrupt, id, data[:]); err == nil {
		return errors.New("corrupted report was accepted")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"accepted": true, "mrenclave": hex.EncodeToString(r.UniqueID),
		"debug": r.Debug, "security_version": r.SecurityVersion,
		"tcb_status": r.TCBStatus.String(), "tcb_advisories": r.TCBAdvisories,
		"result": payload.Result, "report_bytes": len(payload.Report),
		"wrong_measurement_rejected": true, "wrong_report_data_rejected": true,
		"tampered_report_rejected": true,
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
