// Package worker implements the enclave's measured runtime. The same logic is
// exercised without SGX in development, never claimed as hardware attestation.
package worker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/perfclock"
	"certified-data-processing-trading/pkg/protocol"
)

type Ledger interface {
	Trade(context.Context, uint64, bool) (chain.Trade, error)
}
type Prover func([]byte) ([]byte, error)
type Info struct {
	Domain      protocol.Domain `json:"domain"`
	PublicKey   []byte          `json:"public_key"`
	Report      []byte          `json:"report"`
	Development bool            `json:"development"`
}
type DBInput struct {
	Parameters analyzer.Parameters `json:"parameters"`
	PublicKey  []byte              `json:"public_key"`
}
type DOInput struct {
	Key []byte `json:"key"`
}
type Request struct {
	Nonce     string          `json:"nonce"`
	Body      json.RawMessage `json:"body"`
	Signature []byte          `json:"signature"`
}
type Execution struct {
	Receipt          protocol.Receipt `json:"receipt"`
	TotalNanoseconds int64            `json:"total_nanoseconds"`
	Nanoseconds      map[string]int64 `json:"nanoseconds"`
}
type InitializationTimings struct {
	KeyAndCertificate int64 `json:"key_and_certificate_ns"`
	Report            int64 `json:"report_ns"`
	Total             int64 `json:"total_ns"`
}
type Server struct {
	mu             sync.Mutex
	ledger         Ledger
	domain         protocol.Domain
	key            *ecdsa.PrivateKey
	info           Info
	cert           tls.Certificate
	input          func() ([]byte, error)
	nonces         map[string]bool
	db             *DBInput
	do             *DOInput
	execution      *Execution
	aborted        bool
	initialization InitializationTimings
}

const MaxMessage = 1 << 20 // Parameters and requests, not bulk input ciphertext.
func New(ledger Ledger, d protocol.Domain, input func() ([]byte, error), prover Prover, development bool) (*Server, error) {
	if d.ChainID == 0 || d.TID == 0 || ledger == nil || input == nil {
		return nil, errors.New("invalid worker configuration")
	}
	if !development && prover == nil {
		return nil, errors.New("hardware attestation required")
	}
	start := perfclock.Now()
	k, e := ethcrypto.GenerateKey()
	if e != nil {
		return nil, e
	}
	tlsKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "work2-enclave"}, NotBefore: time.Unix(0, 0), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &tlsKey.PublicKey, tlsKey)
	if e != nil {
		return nil, e
	}
	s := &Server{ledger: ledger, domain: d, key: k, input: input, nonces: map[string]bool{}, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: tlsKey}}
	s.info = Info{Domain: d, PublicKey: ethcrypto.FromECDSAPub(&k.PublicKey), Development: development}
	s.initialization.KeyAndCertificate = perfclock.Since(start).Nanoseconds()
	if !development {
		reportStart := perfclock.Now()
		binding := ReportData(d, s.info.PublicKey, der)
		s.info.Report, e = prover(binding)
		if e != nil {
			return nil, e
		}
		s.initialization.Report = perfclock.Since(reportStart).Nanoseconds()
	}
	s.initialization.Total = perfclock.Since(start).Nanoseconds()
	return s, nil
}

// Does not include OS/enclave loading or the ledger lookup preceding New.
func (s *Server) InitializationTimings() InitializationTimings { return s.initialization }

// The first half binds this trade's signing key; the second binds the TLS channel.
func ReportData(d protocol.Domain, pk, certificate []byte) []byte {
	h := protocol.AttestationBinding(d, pk)
	c := sha256.Sum256(certificate)
	return append(h[:], c[:]...)
}
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.cert}}
}
func (s *Server) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert.Certificate[0]})
}
func AuthDigest(d protocol.Domain, pk []byte, path, nonce string, body []byte) protocol.Hash {
	h := protocol.H(body)
	return protocol.H(protocol.Encode([]byte("WORK2_ACCOUNT_AUTH_V1"), d.Bytes(), pk, []byte(path), []byte(nonce), h[:]))
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/attestation", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		write(w, s.info)
	})
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.nonces) >= 1024 {
			http.Error(w, "challenge capacity", 429)
			return
		}
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			http.Error(w, "random generation failed", 500)
			return
		}
		n := hex.EncodeToString(b)
		s.nonces[n] = true
		write(w, map[string]string{"nonce": n})
	})
	for _, path := range []string{"/db-input", "/do-input", "/execute"} {
		mux.HandleFunc(path, s.authorized)
	}
	return mux
}
func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) authorized(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.TLS == nil {
		http.Error(w, "TLS POST required", 400)
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMessage))
	if e != nil {
		http.Error(w, "request too large", 413)
		return
	}
	var req Request
	if e = protocol.StrictJSON(b, &req); e != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.nonces[req.Nonce] {
		http.Error(w, "unknown or consumed challenge", 401)
		return
	}
	delete(s.nonces, req.Nonce)
	signer, e := protocol.Recover(AuthDigest(s.domain, s.info.PublicKey, r.URL.Path, req.Nonce, req.Body), req.Signature)
	if e != nil {
		http.Error(w, "invalid identity signature", 401)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	t, e := s.ledger.Trade(ctx, s.domain.TID, true)
	if e != nil {
		http.Error(w, "chain unavailable", 503)
		return
	}
	if t.Status != 3 || t.EnclaveKey != ethcrypto.PubkeyToAddress(s.key.PublicKey) {
		http.Error(w, "trade or key not ready", 409)
		return
	}
	expected := t.Owner
	if r.URL.Path == "/db-input" {
		expected = t.Buyer
	}
	if signer != expected {
		http.Error(w, "wrong account", 403)
		return
	}
	if s.aborted {
		http.Error(w, "execution aborted", 409)
		return
	}
	switch r.URL.Path {
	case "/db-input":
		if s.db != nil {
			http.Error(w, "DB input already fixed", 409)
			return
		}
		var v DBInput
		if protocol.StrictJSON(req.Body, &v) != nil || analyzer.Validate(v.Parameters) != nil || len(v.PublicKey) != 32 {
			http.Error(w, "invalid DB input", 400)
			return
		}
		// Encrypting a probe also rejects low-order/invalid X25519 public keys.
		if _, e = protocol.EncryptResult(v.PublicKey, nil, s.domain); e != nil {
			http.Error(w, "invalid result public key", 400)
			return
		}
		s.db = &v
		write(w, map[string]bool{"fixed": true})
	case "/do-input":
		if s.do != nil {
			http.Error(w, "DO input already fixed", 409)
			return
		}
		var v DOInput
		if protocol.StrictJSON(req.Body, &v) != nil || len(v.Key) != 32 {
			http.Error(w, "invalid DO input", 400)
			return
		}
		s.do = &v
		write(w, map[string]bool{"fixed": true})
	case "/execute":
		if !bytes.Equal(bytes.TrimSpace(req.Body), []byte("{}")) {
			http.Error(w, "unexpected execution parameters", 400)
			return
		}
		if s.execution != nil {
			write(w, s.execution)
			return
		}
		if s.db == nil || s.do == nil {
			http.Error(w, "inputs missing", 409)
			return
		}
		execution, e := s.execute()
		if e != nil {
			s.aborted = true
			s.eraseInputs()
			http.Error(w, "execution failed; no receipt", 422)
			return
		}
		s.execution = &execution
		s.eraseInputs()
		write(w, s.execution)
	}
}
func (s *Server) eraseInputs() {
	if s.do != nil {
		clear(s.do.Key)
	}
	if s.db != nil {
		clear(s.db.Parameters.Weights)
		s.db.Parameters.Bias = 0
		s.db.Parameters.Threshold = 0
	}
}
func (s *Server) execute() (Execution, error) {
	return Compute(s.domain, s.key, s.input, *s.do, *s.db)
}
