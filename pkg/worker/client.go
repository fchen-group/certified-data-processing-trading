package worker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/protocol"
)

type Verifier func(report []byte, measurement protocol.Hash, data []byte) error
type Client struct {
	URL  string
	Info Info
	HTTP *http.Client
}

// Connect sends no secrets before report verification. Subsequent requests pin
// the certificate cryptographically bound to the verified report.
func Connect(ctx context.Context, endpoint string, d protocol.Domain, measurement protocol.Hash, verify Verifier, devCertificate []byte) (*Client, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.RawQuery != "" || u.User != nil {
		return nil, errors.New("HTTPS worker endpoint required")
	}
	var devDER []byte
	if len(devCertificate) > 0 {
		block, _ := pem.Decode(devCertificate)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid development certificate")
		}
		devDER = block.Bytes
	}
	var cert []byte
	config := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("missing certificate")
		}
		cert = bytes.Clone(cs.PeerCertificates[0].Raw)
		if devDER != nil && !bytes.Equal(cert, devDER) {
			return errors.New("development certificate mismatch")
		}
		return nil
	}}
	tempTransport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
	temp := &http.Client{Transport: tempTransport, Timeout: 30 * time.Second, CheckRedirect: noRedirect}
	defer tempTransport.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint+"/attestation", nil)
	if e != nil {
		return nil, e
	}
	resp, e := temp.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, MaxMessage+1))
	if e != nil || len(raw) > MaxMessage {
		return nil, errors.New("attestation response too large")
	}
	var info Info
	if resp.StatusCode != 200 || protocol.StrictJSON(raw, &info) != nil {
		return nil, errors.New("invalid attestation response")
	}
	if info.Domain != d {
		return nil, errors.New("attestation domain mismatch")
	}
	if _, e = ethcrypto.UnmarshalPubkey(info.PublicKey); e != nil {
		return nil, errors.New("invalid enclave signing key")
	}
	if devDER != nil {
		if !info.Development {
			return nil, errors.New("unexpected hardware mode")
		}
	} else {
		if info.Development || verify == nil {
			return nil, errors.New("hardware verification required")
		}
		if e = verify(info.Report, measurement, ReportData(d, info.PublicKey, cert)); e != nil {
			return nil, e
		}
	}
	pinned := bytes.Clone(cert)
	// Parse now so malformed certificates never get accepted as opaque pins.
	if _, e = x509.ParseCertificate(pinned); e != nil {
		return nil, e
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, pinned) {
			return errors.New("worker certificate changed")
		}
		return nil
	}}
	return &Client{URL: endpoint, Info: info, HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 10 * time.Minute, CheckRedirect: noRedirect}}, nil
}
func noRedirect(*http.Request, []*http.Request) error { return errors.New("redirects forbidden") }
func (c *Client) Close()                              { c.HTTP.CloseIdleConnections() }
func (c *Client) KeyAddress() common.Address {
	p, e := ethcrypto.UnmarshalPubkey(c.Info.PublicKey)
	if e != nil {
		return common.Address{}
	}
	return ethcrypto.PubkeyToAddress(*p)
}
func (c *Client) Send(ctx context.Context, key *ecdsa.PrivateKey, path string, body any, result any) error {
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if e = c.request(ctx, "GET", "/challenge", nil, &challenge); e != nil {
		return e
	}
	signature, e := protocol.Sign(key, AuthDigest(c.Info.Domain, c.Info.PublicKey, path, challenge.Nonce, b))
	if e != nil {
		return e
	}
	encoded, e := json.Marshal(Request{challenge.Nonce, b, signature})
	if e != nil {
		return e
	}
	return c.request(ctx, "POST", path, encoded, result)
}
func (c *Client) request(ctx context.Context, method, path string, body []byte, out any) error {
	r, e := http.NewRequestWithContext(ctx, method, c.URL+path, bytes.NewReader(body))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, MaxMessage+1))
	if e != nil {
		return e
	}
	if len(raw) > MaxMessage {
		return errors.New("response too large")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("worker %s: HTTP %d: %s", path, resp.StatusCode, raw)
	}
	if out != nil {
		return protocol.StrictJSON(raw, out)
	}
	return nil
}
