package experiment

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"certified-data-processing-trading/pkg/chain"
)

func TestGasNonceWaitsForLaggingReadViews(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
			t.Error(e)
			return
		}
		if req.Method != "eth_getTransactionCount" {
			t.Errorf("unexpected non-read operation: %s", req.Method)
		}
		calls++
		nonce := "0x8"
		if calls >= 4 {
			nonce = "0x9"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": nonce})
	}))
	defer server.Close()
	rpc, e := ethclient.Dial(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer rpc.Close()
	c := &chain.Client{RPC: rpc, Config: chain.Config{Development: true}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	expected := uint64(9)
	nonce, e := waitGasNonce(ctx, c, common.Address{}, &expected)
	if e != nil || nonce != expected || calls != 6 {
		t.Fatalf("nonce=%d calls=%d error=%v", nonce, calls, e)
	}
}
func TestGasNonceRejectsUnexpectedActivity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0xa"})
	}))
	defer server.Close()
	rpc, e := ethclient.Dial(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer rpc.Close()
	c := &chain.Client{RPC: rpc, Config: chain.Config{Development: true}}
	expected := uint64(9)
	_, e = waitGasNonce(context.Background(), c, common.Address{}, &expected)
	if e == nil || !strings.Contains(e.Error(), "unexpected account activity") {
		t.Fatal("unexpected transaction was not rejected", e)
	}
}

func TestGasReadRetriesTemporaryMissButNotSemanticError(t *testing.T) {
	calls := 0
	if err := gasRead(context.Background(), func(context.Context) error {
		calls++
		if calls == 1 {
			return ethereum.NotFound
		}
		return nil
	}); err != nil || calls != 2 {
		t.Fatal("temporary miss was not retried", calls, err)
	}
	calls = 0
	if err := gasRead(context.Background(), func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("historical state 0123456789 is not available")
		}
		return nil
	}); err != nil || calls != 2 {
		t.Fatal("historical state availability was not retried", calls, err)
	}
	calls = 0
	semantic := errors.New("contract state mismatch")
	if err := gasRead(context.Background(), func(context.Context) error { calls++; return semantic }); !errors.Is(err, semantic) || calls != 1 {
		t.Fatal("semantic error was retried", calls, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := gasRead(ctx, func(context.Context) error { return ethereum.NotFound }); err == nil {
		t.Fatal("permanent miss ignored")
	}
}

func TestGasInclusionPollsPendingReceiptWithoutErrorBackoff(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "eth_getTransactionReceipt" {
			t.Errorf("unexpected call: %s", req.Method)
		}
		calls++
		response := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": nil}
		if calls > 1 {
			delete(response, "result")
			response["error"] = map[string]any{"code": -32000, "message": "fixture stop"}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	rpc, e := ethclient.Dial(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer rpc.Close()
	c := &chain.Client{RPC: rpc, Config: chain.Config{Development: true}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, e = waitGasInclusion(ctx, c, common.Hash{})
	if e == nil || !strings.Contains(e.Error(), "fixture stop") || calls != 2 {
		t.Fatalf("pending receipt did not reach next inclusion poll: calls=%d error=%v", calls, e)
	}
}
