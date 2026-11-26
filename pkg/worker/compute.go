package worker

import (
	"crypto/ecdsa"
	"errors"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/perfclock"
	"certified-data-processing-trading/pkg/protocol"
)

// Compute consumes an owned ciphertext buffer returned by input. The caller
// must already have authenticated and fixed the transaction inputs. This core
// performs no network authorization and is not an independently exposed API.
// Timings end at receipt creation; deferred buffer erasure runs before return.
func Compute(domain protocol.Domain, key *ecdsa.PrivateKey, input func() ([]byte, error), do DOInput, db DBInput) (Execution, error) {
	out := Execution{Nanoseconds: map[string]int64{}}
	if key == nil || input == nil || domain.ChainID == 0 || domain.TID == 0 {
		return out, errors.New("invalid computation context")
	}
	totalStart := perfclock.Now()
	start := totalStart
	mark := func(name string) {
		end := perfclock.Now()
		out.Nanoseconds[name] = (end - start).Nanoseconds()
		start = end
	}
	encrypted, e := input()
	if e != nil {
		return out, e
	}
	if int64(len(encrypted)) > MaxCiphertextBytes {
		return out, errors.New("ciphertext exceeds size cap")
	}
	defer clear(encrypted)
	mark("load_ciphertext")
	plaintext, e := protocol.OpenInPlace(do.Key, encrypted, domain.Bytes())
	if e != nil {
		return out, e
	}
	defer clear(plaintext)
	d, e := protocol.DecodeDataset(plaintext, MaxRecords, MaxRecordBytes)
	defer func() {
		for _, r := range d.Records {
			clear(r)
		}
		clear(d.Salts)
	}()
	if e != nil {
		return out, e
	}
	mark("decrypt_parse")
	commitment, e := protocol.ReconstructCommitment(d)
	if e != nil {
		return out, e
	}
	mark("commitment")
	result, e := analyzer.Analyze(d.Records, db.Parameters)
	if e != nil {
		return out, e
	}
	defer clear(result)
	mark("analyze")
	ciphertext, e := protocol.EncryptResult(db.PublicKey, result, domain)
	if e != nil {
		return out, e
	}
	signature, e := protocol.Sign(key, protocol.ReceiptDigest(domain, commitment, ciphertext))
	if e != nil {
		return out, e
	}
	out.Receipt = protocol.Receipt{Commitment: commitment, Ciphertext: ciphertext, Signature: signature}
	mark("encrypt_sign")
	out.TotalNanoseconds = (start - totalStart).Nanoseconds()
	return out, nil
}
