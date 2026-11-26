package worker

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/protocol"
)

type ledgerStub struct {
	trade chain.Trade
	err   error
}

func (l *ledgerStub) Trade(context.Context, uint64, bool) (chain.Trade, error) { return l.trade, l.err }

type fixture struct {
	s            *Server
	c            *Client
	ledger       *ledgerStub
	owner, buyer *ecdsa.PrivateKey
	sk           *ecdh.PrivateKey
	key          []byte
	data         protocol.Dataset
	input        *[]byte
	domain       protocol.Domain
}

func setup(t *testing.T) *fixture {
	t.Helper()
	owner, _ := ethcrypto.GenerateKey()
	buyer, _ := ethcrypto.GenerateKey()
	domain := protocol.Domain{ChainID: 31337, Contract: common.HexToAddress("0x1234"), TID: 1}
	d, e := protocol.Prepare([][]byte{[]byte(`{"id":"a","features":[2,3]}`), []byte(`{"id":"b","features":[1,0]}`)})
	if e != nil {
		t.Fatal(e)
	}
	key, _ := protocol.NewKey()
	raw, _ := json.Marshal(d)
	encrypted, _ := protocol.Seal(key, raw, domain.Bytes())
	tree, _ := protocol.Build(d)
	ledger := &ledgerStub{trade: chain.Trade{Owner: ethcrypto.PubkeyToAddress(owner.PublicKey), Buyer: ethcrypto.PubkeyToAddress(buyer.PublicKey), Commitment: tree.Commitment(), Status: 3}}
	s, e := New(ledger, domain, func() ([]byte, error) { return bytes.Clone(encrypted), nil }, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	ledger.trade.EnclaveKey = ethcrypto.PubkeyToAddress(s.key.PublicKey)
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = s.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)
	c, e := Connect(context.Background(), ts.URL, domain, protocol.Hash{}, nil, s.CertificatePEM())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	sk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return &fixture{s, c, ledger, owner, buyer, sk, key, d, &encrypted, domain}
}
func (f *fixture) inputs(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if e := f.c.Send(ctx, f.buyer, "/db-input", DBInput{analyzer.Parameters{Weights: []float64{2, 1}, Threshold: 3}, f.sk.PublicKey().Bytes()}, nil); e != nil {
		t.Fatal(e)
	}
	if e := f.c.Send(ctx, f.owner, "/do-input", DOInput{f.key}, nil); e != nil {
		t.Fatal(e)
	}
}
func TestOnlyDOCanRetrieveReceipt(t *testing.T) {
	f := setup(t)
	f.inputs(t)
	var execution Execution
	ctx := context.Background()
	if e := f.c.Send(ctx, f.buyer, "/execute", struct{}{}, &execution); e == nil {
		t.Fatal("DB received receipt")
	}
	if e := f.c.Send(ctx, f.owner, "/execute", struct{}{}, &execution); e != nil {
		t.Fatal(e)
	}
	if e := protocol.VerifyReceipt(f.domain, execution.Receipt, f.c.KeyAddress()); e != nil {
		t.Fatal(e)
	}
	r, e := protocol.DecryptResult(f.sk.Bytes(), execution.Receipt.Ciphertext, f.domain)
	if e != nil || string(r) != `{"count":2,"above_threshold":1}` {
		t.Fatalf("%s %v", r, e)
	}
	if e := f.c.Send(ctx, f.buyer, "/execute", struct{}{}, &execution); e == nil {
		t.Fatal("cached receipt leaked to DB")
	}
	var again Execution
	if e := f.c.Send(ctx, f.owner, "/execute", struct{}{}, &again); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(again.Receipt.Signature, execution.Receipt.Signature) {
		t.Fatal("execution repeated")
	}
}
func TestIdentityAndInputsCannotBeSubstituted(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if e := f.c.Send(ctx, f.buyer, "/do-input", DOInput{f.key}, nil); e == nil {
		t.Fatal("wrong role accepted")
	}
	f.inputs(t)
	if e := f.c.Send(ctx, f.owner, "/do-input", DOInput{f.key}, nil); e == nil {
		t.Fatal("input replacement allowed")
	}
	f.ledger.trade.EnclaveKey = common.HexToAddress("0x1234")
	if e := f.c.Send(ctx, f.owner, "/execute", struct{}{}, nil); e == nil {
		t.Fatal("unconfirmed instance executed")
	}
}
func TestAuthenticationIsBoundToBodyAndOneUseChallenge(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if e := f.c.request(ctx, "GET", "/challenge", nil, &challenge); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(DOInput{f.key})
	sig, _ := protocol.Sign(f.owner, AuthDigest(f.domain, f.c.Info.PublicKey, "/do-input", challenge.Nonce, body))
	raw, _ := json.Marshal(Request{challenge.Nonce, body, sig})
	if e := f.c.request(ctx, "POST", "/do-input", raw, nil); e != nil {
		t.Fatal(e)
	}
	if e := f.c.request(ctx, "POST", "/do-input", raw, nil); e == nil {
		t.Fatal("replay accepted")
	}
	if e := f.c.request(ctx, "GET", "/challenge", nil, &challenge); e != nil {
		t.Fatal(e)
	}
	sig, _ = protocol.Sign(f.buyer, AuthDigest(f.domain, f.c.Info.PublicKey, "/db-input", challenge.Nonce, []byte(`{}`)))
	body, _ = json.Marshal(DBInput{analyzer.Parameters{Weights: []float64{1}}, f.sk.PublicKey().Bytes()})
	raw, _ = json.Marshal(Request{challenge.Nonce, body, sig})
	if e := f.c.request(ctx, "POST", "/db-input", raw, nil); e == nil {
		t.Fatal("unsigned body accepted")
	}
}
func TestCorruptInputAbortsWithoutReceipt(t *testing.T) {
	f := setup(t)
	f.inputs(t)
	(*f.input)[len(*f.input)-1] ^= 1
	if e := f.c.Send(context.Background(), f.owner, "/execute", struct{}{}, nil); e == nil {
		t.Fatal("corrupt ciphertext accepted")
	}
	if f.s.execution != nil || !f.s.aborted {
		t.Fatal("receipt on failed computation")
	}
}
func TestChangedInputIsReportedAsChangedCommitment(t *testing.T) {
	f := setup(t)
	f.inputs(t)
	f.data.Records[0] = []byte(`{"id":"a","features":[9,9]}`)
	raw, _ := json.Marshal(f.data)
	*f.input, _ = protocol.Seal(f.key, raw, f.domain.Bytes())
	var ex Execution
	if e := f.c.Send(context.Background(), f.owner, "/execute", struct{}{}, &ex); e != nil {
		t.Fatal(e)
	}
	if ex.Receipt.Commitment == f.ledger.trade.Commitment {
		t.Fatal("actual input not bound")
	}
}
func TestProductionNeverAcceptsDevelopmentAttestation(t *testing.T) {
	f := setup(t)
	if _, e := Connect(context.Background(), f.c.URL, f.domain, protocol.Hash{}, func([]byte, protocol.Hash, []byte) error { return nil }, nil); e == nil {
		t.Fatal("development accepted as SGX")
	}
	wrong := f.domain
	wrong.TID++
	if _, e := Connect(context.Background(), f.c.URL, wrong, protocol.Hash{}, nil, f.s.CertificatePEM()); e == nil {
		t.Fatal("wrong transaction accepted")
	}
}
func TestAttestationBindsCertificateAndSigningKey(t *testing.T) {
	domain := protocol.Domain{ChainID: 1, Contract: common.HexToAddress("0x01"), TID: 7}
	s, e := New(&ledgerStub{}, domain, func() ([]byte, error) { return nil, nil }, func(b []byte) ([]byte, error) { return b, nil }, false)
	if e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = s.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	verifier := func(report []byte, _ protocol.Hash, data []byte) error {
		if !bytes.Equal(report, data) {
			return fmt.Errorf("binding mismatch")
		}
		return nil
	}
	c, e := Connect(context.Background(), ts.URL, domain, protocol.Hash{}, verifier, nil)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	s.info.PublicKey = ethcrypto.FromECDSAPub(&ecdsaKey(t).PublicKey)
	if _, e = Connect(context.Background(), ts.URL, domain, protocol.Hash{}, verifier, nil); e == nil {
		t.Fatal("unattested signing key accepted")
	}
}
func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	k, e := ethcrypto.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	return k
}

func TestFullAdultEncryptedInputAndSignedReceipt(t *testing.T) {
	f := setup(t)
	row := []byte("39, ?, 77516, Bachelors, 13, Never-married, Adm-clerical, Not-in-family, White, Male, 2174, 0, 40, United-States, <=50K. ")
	data, err := protocol.Prepare([][]byte{row})
	if err != nil {
		t.Fatal(err)
	}
	tree, err := protocol.Build(data)
	if err != nil {
		t.Fatal(err)
	}
	f.ledger.trade.Commitment = tree.Commitment()
	plain, _ := json.Marshal(data)
	*f.input, err = protocol.Seal(f.key, plain, f.domain.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.c.Send(ctx, f.buyer, "/db-input", DBInput{analyzer.Parameters{Task: analyzer.AdultStatistics}, f.sk.PublicKey().Bytes()}, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Send(ctx, f.owner, "/do-input", DOInput{f.key}, nil); err != nil {
		t.Fatal(err)
	}
	var ex Execution
	if err := f.c.Send(ctx, f.owner, "/execute", struct{}{}, &ex); err != nil {
		t.Fatal(err)
	}
	if ex.Receipt.Commitment != tree.Commitment() {
		t.Fatal("execution did not bind full original bytes")
	}
	if err := protocol.VerifyReceipt(f.domain, ex.Receipt, f.c.KeyAddress()); err != nil {
		t.Fatal(err)
	}
	result, err := protocol.DecryptResult(f.sk.Bytes(), ex.Receipt.Ciphertext, f.domain)
	if err != nil {
		t.Fatal(err)
	}
	var got analyzer.StatisticsResult
	if err := json.Unmarshal(result, &got); err != nil || got.Count != 1 || got.Age.Mean != 39 || got.HoursPerWeek.Mean != 40 {
		t.Fatal("incorrect analysis", got, err)
	}
	if err := f.c.Send(ctx, f.buyer, "/execute", struct{}{}, &ex); err == nil {
		t.Fatal("receipt leaked to DB")
	}
}
