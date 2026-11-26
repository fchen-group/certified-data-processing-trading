package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestResultHPKEInteroperability(t *testing.T) {
	// DB keys retain the raw X25519 representation used by the CLI.
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := hpke.NewDHKEMPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	public, err := hpke.NewDHKEMPublicKey(sk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	d := Domain{ChainID: 11155111, Contract: common.HexToAddress("0x1234"), TID: 17}
	// Encode the documented application info independently of resultInfo.
	info := Encode([]byte("WORK2_RESULT_HPKE_V1"), Encode(U64(d.ChainID), d.Contract[:], U64(d.TID)))
	for _, size := range []int{0, 1, 128, 512, 4096, 256 * 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			plain := bytes.Repeat([]byte{0xa5}, size)
			sealed, err := EncryptResult(sk.PublicKey().Bytes(), plain, d)
			if err != nil {
				t.Fatal(err)
			}
			// X25519 encapsulation is 32 bytes; the GCM tag is 16 bytes.
			if len(sealed) != size+48 {
				t.Fatalf("unexpected wire size: %d", len(sealed))
			}
			got, err := DecryptResult(sk.Bytes(), sealed, d)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("round trip: %v", err)
			}
			recipient, err := hpke.NewRecipient(sealed[:32], private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
			if err != nil {
				t.Fatal(err)
			}
			got, err = recipient.Open(nil, sealed[32:])
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("standard HPKE recipient: %v", err)
			}
			enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, err := sender.Seal(nil, plain)
			if err != nil {
				t.Fatal(err)
			}
			got, err = DecryptResult(sk.Bytes(), append(enc, ciphertext...), d)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("standard HPKE sender: %v", err)
			}
			if bytes.Equal(sealed, append(enc, ciphertext...)) {
				t.Fatal("repeated encapsulation")
			}
		})
	}
}

func TestResultHPKERejectsInvalidInputs(t *testing.T) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := Domain{ChainID: 11155111, Contract: common.HexToAddress("0x1234"), TID: 17}
	sealed, err := EncryptResult(sk.PublicKey().Bytes(), []byte("private result"), d)
	if err != nil {
		t.Fatal(err)
	}
	reject := func(t *testing.T, key, ciphertext []byte, domain Domain) {
		t.Helper()
		if got, err := DecryptResult(key, ciphertext, domain); err == nil || len(got) != 0 {
			t.Fatalf("invalid input returned plaintext or succeeded: %v", err)
		}
	}
	t.Run("transaction context", func(t *testing.T) {
		for _, changed := range []Domain{
			{ChainID: d.ChainID + 1, Contract: d.Contract, TID: d.TID},
			{ChainID: d.ChainID, Contract: common.HexToAddress("0x5678"), TID: d.TID},
			{ChainID: d.ChainID, Contract: d.Contract, TID: d.TID + 1},
		} {
			reject(t, sk.Bytes(), sealed, changed)
		}
	})
	t.Run("wrong recipient", func(t *testing.T) {
		other, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		reject(t, other.Bytes(), sealed, d)
	})
	t.Run("truncation and tampering", func(t *testing.T) {
		for n := 0; n < len(sealed); n++ {
			reject(t, sk.Bytes(), sealed[:n], d)
		}
		for _, pos := range []int{0, 31, 32, len(sealed) - 1} {
			changed := bytes.Clone(sealed)
			changed[pos] ^= 1
			reject(t, sk.Bytes(), changed, d)
		}
		reject(t, sk.Bytes(), append(bytes.Clone(sealed), 0), d)
		changed := bytes.Clone(sealed)
		clear(changed[:32])
		reject(t, sk.Bytes(), changed, d)
	})
	t.Run("malformed keys", func(t *testing.T) {
		for _, n := range []int{0, 31, 33} {
			if _, err := EncryptResult(make([]byte, n), nil, d); err == nil {
				t.Fatalf("accepted %d-byte public key", n)
			}
			reject(t, make([]byte, n), sealed, d)
		}
		for _, first := range []byte{0, 1} {
			lowOrder := make([]byte, 32)
			lowOrder[0] = first
			if _, err := EncryptResult(lowOrder, nil, d); err == nil {
				t.Fatal("accepted low-order public key")
			}
		}
	})
}
