package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"math"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func data(n int) Dataset {
	d := Dataset{}
	for i := 0; i < n; i++ {
		d.Records = append(d.Records, []byte(fmt.Sprint(i)))
		d.Salts = append(d.Salts, H(U64(uint64(i))))
	}
	return d
}
func TestMerkleAllPositionsAndOddSizes(t *testing.T) {
	for n := 1; n <= 257; n++ {
		d := data(n)
		tree, e := Build(d)
		if e != nil {
			t.Fatal(e)
		}
		for i := 1; i <= n; i++ {
			p, e := tree.Proof(uint64(i))
			if e != nil {
				t.Fatal(e)
			}
			if !Verify(tree.Commitment(), uint64(n), uint64(i), d.Records[i-1], d.Salts[i-1], p) {
				t.Fatalf("n=%d i=%d", n, i)
			}
			if Verify(tree.Commitment(), uint64(n+1), uint64(i), d.Records[i-1], d.Salts[i-1], p) {
				t.Fatal("wrong count accepted")
			}
			if Verify(tree.Commitment(), uint64(n), uint64(i), []byte("other"), d.Salts[i-1], p) {
				t.Fatal("wrong record accepted")
			}
		}
	}
}
func TestCommitmentBindsOrderCountSaltAndEncoding(t *testing.T) {
	d := data(3)
	original, _ := Build(d)
	d.Records[0], d.Records[1] = d.Records[1], d.Records[0]
	reordered, _ := Build(d)
	if original.Commitment() == reordered.Commitment() {
		t.Fatal("order not bound")
	}
	d = data(3)
	d.Salts[0][0] ^= 1
	salted, _ := Build(d)
	if original.Commitment() == salted.Commitment() {
		t.Fatal("salt not bound")
	}
	if bytes.Equal(Encode([]byte("ab"), []byte("c")), Encode([]byte("a"), []byte("bc"))) {
		t.Fatal("ambiguous encoding")
	}
	p, _ := original.Proof(1)
	p.Siblings = append(p.Siblings, Hash{})
	d = data(3)
	if Verify(original.Commitment(), 3, 1, d.Records[0], d.Salts[0], p) {
		t.Fatal("extra proof accepted")
	}
	if _, e := Build(Dataset{Records: [][]byte{{1}}}); e == nil {
		t.Fatal("missing salt accepted")
	}
}
func TestSamplingBoundsAndChallenge(t *testing.T) {
	for _, n := range []uint64{1, 2, 10, 100, 1000, 1000000} {
		for _, rho := range []float64{.001, .01, .1, .5} {
			for _, eps := range []float64{.1, .01, .001} {
				m, e := SampleSize(n, rho, eps)
				if e != nil {
					t.Fatal(e)
				}
				// Exact finite-population probability of missing ceil(rho*N) bad records.
				bad := uint64(math.Ceil(rho * float64(n)))
				p := 1.0
				for i := uint64(0); i < m; i++ {
					if n-bad <= i {
						p = 0
						break
					}
					p *= float64(n-bad-i) / float64(n-i)
				}
				if p > eps*(1+1e-12) {
					t.Fatalf("unsafe m=%d probability=%g epsilon=%g", m, p, eps)
				}
			}
		}
	}
	m, _ := SampleSize(1000000, .01, .001)
	if m != 688 {
		t.Fatal(m)
	}
	for _, nm := range [][2]uint64{{1, 1}, {23, 23}, {1000000, 100}, {math.MaxUint64, 5}} {
		s, e := Sample(nm[0], nm[1], nil)
		if e != nil {
			t.Fatal(e)
		}
		if uint64(len(s)) != nm[1] {
			t.Fatal("wrong size")
		}
		var last uint64
		for _, i := range s {
			if i <= last || i > nm[0] {
				t.Fatal("invalid sample")
			}
			last = i
		}
	}
	for _, v := range [][2]float64{{0, .1}, {1, .1}, {.1, 0}, {.1, 1}, {math.NaN(), .1}} {
		if _, e := SampleSize(10, v[0], v[1]); e == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	if _, e := ChallengeHash([]uint64{2, 1}); e == nil {
		t.Fatal("unordered challenge")
	}
}
func TestSampleResponseMustMatchChallenge(t *testing.T) {
	d := data(5)
	tree, _ := Build(d)
	indices := []uint64{1, 3}
	r, _ := Respond(d, indices)
	if e := VerifySamples(tree.Commitment(), 5, indices, r); e != nil {
		t.Fatal(e)
	}
	r[0], r[1] = r[1], r[0]
	if e := VerifySamples(tree.Commitment(), 5, indices, r); e == nil {
		t.Fatal("substituted samples accepted")
	}
}
func TestEncryptionAndSignatureDomains(t *testing.T) {
	domain := Domain{ChainID: 31337, Contract: common.HexToAddress("0x1234"), TID: 1}
	other := domain
	other.TID++
	key, _ := NewKey()
	p := []byte("sensitive record")
	c, e := Seal(key, p, domain.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	if got, e := Open(key, c, domain.Bytes()); e != nil || !bytes.Equal(got, p) {
		t.Fatal("decrypt")
	}
	if _, e := Open(key, c, other.Bytes()); e == nil {
		t.Fatal("cross-trade input")
	}
	c[len(c)-1] ^= 1
	if _, e := Open(key, c, domain.Bytes()); e == nil {
		t.Fatal("modified ciphertext")
	}
	sk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	encrypted, e := EncryptResult(sk.PublicKey().Bytes(), p, domain)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := DecryptResult(sk.Bytes(), encrypted, domain); e != nil || !bytes.Equal(got, p) {
		t.Fatal("result decrypt")
	}
	if _, e := DecryptResult(sk.Bytes(), encrypted, other); e == nil {
		t.Fatal("cross-trade result")
	}
	sign, _ := ethcrypto.GenerateKey()
	r := Receipt{Commitment: H(p), Ciphertext: encrypted}
	r.Signature, _ = Sign(sign, ReceiptDigest(domain, r.Commitment, r.Ciphertext))
	if e := VerifyReceipt(domain, r, ethcrypto.PubkeyToAddress(sign.PublicKey)); e != nil {
		t.Fatal(e)
	}
	if e := VerifyReceipt(other, r, ethcrypto.PubkeyToAddress(sign.PublicKey)); e == nil {
		t.Fatal("cross-trade receipt")
	}
	r.Ciphertext[0] ^= 1
	if e := VerifyReceipt(domain, r, ethcrypto.PubkeyToAddress(sign.PublicKey)); e == nil {
		t.Fatal("modified result")
	}
	if _, e := EncryptResult(make([]byte, 32), nil, domain); e == nil {
		t.Fatal("low-order public key accepted")
	}
}
func FuzzMerkleTampering(f *testing.F) {
	f.Add([]byte("different"), uint8(2))
	f.Fuzz(func(t *testing.T, record []byte, index uint8) {
		d := data(7)
		tree, _ := Build(d)
		p, _ := tree.Proof(3)
		i := uint64(index)
		valid := Verify(tree.Commitment(), 7, i, record, d.Salts[2], p)
		if valid && (i != 3 || !bytes.Equal(record, d.Records[2])) {
			t.Fatal("forged membership")
		}
	})
}
