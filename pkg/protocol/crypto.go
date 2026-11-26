package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type Domain struct {
	ChainID  uint64         `json:"chain_id"`
	Contract common.Address `json:"contract"`
	TID      uint64         `json:"tid"`
}

func (d Domain) Bytes() []byte { return Encode(U64(d.ChainID), d.Contract[:], U64(d.TID)) }

type Receipt struct {
	Commitment Hash   `json:"commitment"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  []byte `json:"signature"`
}

func ReceiptDigest(d Domain, c Hash, out []byte) Hash {
	types := []string{"string", "uint256", "address", "uint256", "bytes32", "bytes32"}
	args := make(abi.Arguments, len(types))
	for i, s := range types {
		t, e := abi.NewType(s, "", nil)
		if e != nil {
			panic(e)
		}
		args[i] = abi.Argument{Type: t}
	}
	b, e := args.Pack("WORK2_RECEIPT_V1", new(big.Int).SetUint64(d.ChainID), d.Contract, new(big.Int).SetUint64(d.TID), [32]byte(c), ethcrypto.Keccak256Hash(out))
	if e != nil {
		panic(e)
	}
	return Hash(ethcrypto.Keccak256Hash(b))
}
func Sign(key *ecdsa.PrivateKey, h Hash) ([]byte, error) {
	s, e := ethcrypto.Sign(h[:], key)
	if e != nil {
		return nil, e
	}
	s[64] += 27
	return s, nil
}
func Recover(h Hash, s []byte) (common.Address, error) {
	if len(s) != 65 || (s[64] != 27 && s[64] != 28) {
		return common.Address{}, errors.New("invalid signature")
	}
	c := append([]byte(nil), s...)
	c[64] -= 27
	r, v := new(big.Int).SetBytes(c[:32]), new(big.Int).SetBytes(c[32:64])
	if !ethcrypto.ValidateSignatureValues(c[64], r, v, true) {
		return common.Address{}, errors.New("noncanonical signature")
	}
	pk, e := ethcrypto.SigToPub(h[:], c)
	if e != nil {
		return common.Address{}, e
	}
	return ethcrypto.PubkeyToAddress(*pk), nil
}
func VerifyReceipt(d Domain, r Receipt, expected common.Address) error {
	if len(r.Ciphertext) == 0 || expected == (common.Address{}) {
		return errors.New("empty receipt or key")
	}
	a, e := Recover(ReceiptDigest(d, r.Commitment, r.Ciphertext), r.Signature)
	if e != nil {
		return e
	}
	if a != expected {
		return errors.New("receipt signer mismatch")
	}
	return nil
}
func NewKey() ([]byte, error) { k := make([]byte, 32); _, e := rand.Read(k); return k, e }
func Seal(k, plaintext, aad []byte) ([]byte, error) {
	if len(k) != 32 {
		return nil, errors.New("AES-256 key required")
	}
	c, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(c)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return g.Seal(nonce, nonce, plaintext, aad), nil
}
func Open(k, encrypted, aad []byte) ([]byte, error) {
	return open(k, encrypted, aad, false)
}

// OpenInPlace consumes an owned ciphertext buffer; callers must not reuse it.
func OpenInPlace(k, encrypted, aad []byte) ([]byte, error) {
	return open(k, encrypted, aad, true)
}

func open(k, encrypted, aad []byte, inPlace bool) ([]byte, error) {
	if len(k) != 32 {
		return nil, errors.New("AES-256 key required")
	}
	c, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(c)
	if e != nil {
		return nil, e
	}
	if len(encrypted) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("truncated ciphertext")
	}
	var dst []byte
	if inPlace {
		dst = encrypted[g.NonceSize():g.NonceSize()]
	}
	return g.Open(dst, encrypted[:g.NonceSize()], encrypted[g.NonceSize():], aad)
}

// resultInfo binds the RFC 9180 HPKE context to this protocol and transaction.
func resultInfo(d Domain) []byte {
	return Encode([]byte("WORK2_RESULT_HPKE_V1"), d.Bytes())
}

// EncryptResult uses HPKE base mode with DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256, and AES-256-GCM. The wire format is enc || ciphertext;
// the sender is authenticated separately by the signed execution receipt.
func EncryptResult(pk, out []byte, d Domain) ([]byte, error) {
	recipient, e := hpke.DHKEM(ecdh.X25519()).NewPublicKey(pk)
	if e != nil {
		return nil, e
	}
	return hpke.Seal(recipient, hpke.HKDFSHA256(), hpke.AES256GCM(), resultInfo(d), out)
}

func DecryptResult(sk, out []byte, d Domain) ([]byte, error) {
	secret, e := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(sk)
	if e != nil {
		return nil, e
	}
	return hpke.Open(secret, hpke.HKDFSHA256(), hpke.AES256GCM(), resultInfo(d), out)
}
func AttestationBinding(d Domain, pk []byte) Hash { return H(Encode(d.Bytes(), pk)) }
