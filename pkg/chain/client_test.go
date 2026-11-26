package chain

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Only exercises the TLS trust anchor; it is not a consensus-validation test.
func TestProductionRPCPinAndChainID(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.Method != "eth_chainId" {
			t.Errorf("unexpected RPC: %s", request.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": "0x1"})
	}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	s.StartTLS()
	defer s.Close()
	h := sha256.Sum256(s.Certificate().RawSubjectPublicKeyInfo)
	cfg := Config{RPC: s.URL, ChainID: 1, RPCSPKI: hex.EncodeToString(h[:])}
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	cfg.RPCSPKI = strings.Repeat("00", 32)
	if c, err := Dial(context.Background(), cfg); err == nil {
		c.Close()
		t.Fatal("accepted wrong RPC public key")
	}
	cfg.RPCSPKI = hex.EncodeToString(h[:])
	cfg.ChainID = 2
	if c, err := Dial(context.Background(), cfg); err == nil {
		c.Close()
		t.Fatal("accepted wrong chain ID")
	}
	cfg.RPC = "http://127.0.0.1:1"
	if _, err := Dial(context.Background(), cfg); err == nil {
		t.Fatal("production accepted plaintext RPC")
	}
}

func TestSettlementBudgetIncludesFreshnessAndElapsedTime(t *testing.T) {
	start := time.Unix(1000, 0)
	for _, tc := range []struct {
		name                    string
		block, deadline, margin uint64
		elapsed                 time.Duration
		development, ok         bool
	}{
		{"normal", 1000, 1100, 30, time.Second, true, true},
		{"exact-margin", 1000, 1030, 30, 0, true, false},
		{"dispatch-reserve", 1000, 1035, 30, 0, true, false},
		{"slow-header", 1000, 1050, 30, 20 * time.Second, true, false},
		{"stale-header-response", 1000, 1200, 30, 31 * time.Second, true, false},
		{"wall-clock-removes-stale-block-slack", 900, 1030, 30, 0, false, false},
		{"head-too-old", 800, 1200, 30, 0, false, false},
		{"head-in-future", 1010, 1200, 30, 0, false, false},
		{"production-normal", 995, 1100, 30, time.Second, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := settlementBudget(tc.block, tc.deadline, tc.margin, start, start.Add(tc.elapsed), tc.development)
			if (err == nil) != tc.ok {
				t.Fatalf("accepted=%v, want %v: %v", err == nil, tc.ok, err)
			}
		})
	}
}

func TestOrdinaryGasLimitBounds(t *testing.T) {
	gas, err := OrdinaryGasLimit(249815, 60_000_000)
	if err != nil || gas <= 261828 {
		t.Fatalf("observed confirmation race lacks headroom: gas=%d err=%v", gas, err)
	}
	for _, test := range [][2]uint64{{0, 60_000_000}, {249815, 260000}, {1 << 24, 60_000_000}, {^uint64(0), ^uint64(0)}} {
		if _, err := OrdinaryGasLimit(test[0], test[1]); err == nil {
			t.Fatalf("accepted unsafe gas bounds: %v", test)
		}
	}
}
