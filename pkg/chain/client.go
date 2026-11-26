// Package chain accesses TSC through a pinned, operator-controlled Ethereum node.
package chain

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"certified-data-processing-trading/pkg/protocol"
)

//go:embed tsc.abi.json
var ABIJSON string
var ABI = mustABI()

func mustABI() abi.ABI {
	a, e := abi.JSON(strings.NewReader(ABIJSON))
	if e != nil {
		panic(e)
	}
	return a
}

type Config struct {
	RPC         string         `json:"rpc"`
	ChainID     uint64         `json:"chain_id"`
	Contract    common.Address `json:"contract"`
	CodeHash    common.Hash    `json:"code_hash"`
	RPCSPKI     string         `json:"rpc_spki_sha256"`
	Development bool           `json:"development"`
}
type Client struct {
	RPC    *ethclient.Client
	Config Config
	bound  *bind.BoundContract
}

// Production trusts this independently operated node's consensus validation.
// Its URL, SPKI pin, chain ID and contract code hash MUST be in the measured image.
func Dial(ctx context.Context, c Config) (*Client, error) {
	u, e := url.Parse(c.RPC)
	if e != nil {
		return nil, e
	}
	transport := &http.Transport{}
	if c.ChainID == 0 {
		return nil, errors.New("chain ID required")
	}
	if c.Development {
		if u.Scheme != "http" || (u.Hostname() != "localhost" && !net.ParseIP(u.Hostname()).IsLoopback()) {
			return nil, errors.New("development RPC must be loopback HTTP")
		}
	} else {
		pin, e := hex.DecodeString(c.RPCSPKI)
		if e != nil || len(pin) != 32 || u.Scheme != "https" {
			return nil, errors.New("production requires HTTPS and a 32-byte RPC SPKI pin")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("missing RPC certificate")
			}
			h := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if hex.EncodeToString(h[:]) != c.RPCSPKI {
				return errors.New("RPC pin mismatch")
			}
			return nil
		}}
	}
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("RPC redirects forbidden") }}
	r, e := rpc.DialOptions(ctx, c.RPC, rpc.WithHTTPClient(httpClient))
	if e != nil {
		return nil, e
	}
	cl := &Client{RPC: ethclient.NewClient(r), Config: c}
	fail := func(e error) (*Client, error) { cl.Close(); return nil, e }
	id, e := cl.RPC.ChainID(ctx)
	if e != nil {
		return fail(e)
	}
	if id.Cmp(new(big.Int).SetUint64(c.ChainID)) != 0 {
		return fail(errors.New("chain ID mismatch"))
	}
	if c.Contract != (common.Address{}) {
		if c.CodeHash == (common.Hash{}) {
			return fail(errors.New("contract code hash required"))
		}
		code, e := cl.RPC.CodeAt(ctx, c.Contract, nil)
		if e != nil {
			return fail(e)
		}
		if len(code) == 0 || ethcrypto.Keccak256Hash(code) != c.CodeHash {
			return fail(errors.New("contract code hash mismatch"))
		}
		cl.bound = bind.NewBoundContract(c.Contract, ABI, cl.RPC, cl.RPC, cl.RPC)
	}
	return cl, nil
}
func (c *Client) Close() { c.RPC.Close() }
func (c *Client) Domain(tid uint64) protocol.Domain {
	return protocol.Domain{ChainID: c.Config.ChainID, Contract: c.Config.Contract, TID: tid}
}
func (c *Client) FinalHeader(ctx context.Context) (*types.Header, error) {
	if c.Config.Development {
		return c.RPC.HeaderByNumber(ctx, nil)
	}
	return c.RPC.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
}
func (c *Client) Call(ctx context.Context, final bool, method string, args ...any) ([]any, error) {
	if c.bound == nil {
		return nil, errors.New("contract not configured")
	}
	opts := &bind.CallOpts{Context: ctx}
	if final {
		h, e := c.FinalHeader(ctx)
		if e != nil {
			return nil, e
		}
		opts.BlockNumber = h.Number
	}
	var out []any
	e := c.bound.Call(opts, &out, method, args...)
	return out, e
}

type Audit struct {
	Owner                               common.Address
	Batch, Version, Description, Policy [32]byte
	Records                             uint64
	Commitment                          [32]byte
	Deadline                            uint64
	Challenge                           [32]byte
	Status                              uint8
	Did                                 *big.Int
}
type Trade struct {
	Did                             *big.Int
	Owner, Buyer                    common.Address
	Source, Measurement, Commitment [32]byte
	Price                           *big.Int
	Duration, Deadline              uint64
	OwnerKey, BuyerKey, EnclaveKey  common.Address
	Status                          uint8
}

func (c *Client) Audit(ctx context.Context, id uint64, final bool) (Audit, error) {
	o, e := c.Call(ctx, final, "getAudit", new(big.Int).SetUint64(id))
	if e != nil {
		return Audit{}, e
	}
	if len(o) != 1 {
		return Audit{}, errors.New("invalid audit response")
	}
	return *abi.ConvertType(o[0], new(Audit)).(*Audit), nil
}
func (c *Client) Trade(ctx context.Context, id uint64, final bool) (Trade, error) {
	o, e := c.Call(ctx, final, "getTrade", new(big.Int).SetUint64(id))
	if e != nil {
		return Trade{}, e
	}
	if len(o) != 1 {
		return Trade{}, errors.New("invalid trade response")
	}
	return *abi.ConvertType(o[0], new(Trade)).(*Trade), nil
}
func (c *Client) Send(ctx context.Context, key *ecdsa.PrivateKey, value *big.Int, method string, args ...any) (*types.Receipt, error) {
	if c.bound == nil {
		return nil, errors.New("contract not configured")
	}
	// Estimation observes only the current state. In particular, a concurrent
	// confirmKey can make this call the more expensive second confirmation.
	input, e := ABI.Pack(method, args...)
	if e != nil {
		return nil, e
	}
	estimate, e := c.RPC.EstimateGas(ctx, ethereum.CallMsg{From: ethcrypto.PubkeyToAddress(key.PublicKey), To: &c.Config.Contract, Value: value, Data: input})
	if e != nil {
		return nil, e
	}
	header, e := c.RPC.HeaderByNumber(ctx, nil)
	if e != nil {
		return nil, e
	}
	gas, e := OrdinaryGasLimit(estimate, header.GasLimit)
	if e != nil {
		return nil, e
	}
	tx, e := c.prepare(ctx, key, value, gas, method, args...)
	if e != nil {
		return nil, e
	}
	if e = c.RPC.SendTransaction(ctx, tx); e != nil {
		return nil, e
	}
	return c.Wait(ctx, tx)
}

// OrdinaryGasLimit adds headroom for public calls, not a guarantee against arbitrary state
// changes. Settlement uses its separate local budget and never estimates remotely.
func OrdinaryGasLimit(estimate, blockLimit uint64) (uint64, error) {
	const transactionLimit = uint64(1 << 24)
	limit := min(blockLimit, transactionLimit)
	if estimate == 0 || estimate > limit {
		return 0, errors.New("gas estimate outside transaction or block limit")
	}
	reserve := estimate/5 + 50_000
	if reserve > limit-estimate {
		return 0, errors.New("insufficient gas headroom within transaction or block limit")
	}
	return estimate + reserve, nil
}

// A nonzero gasLimit skips remote estimation; NoSend alone does not do so.
func (c *Client) prepare(ctx context.Context, key *ecdsa.PrivateKey, value *big.Int, gasLimit uint64, method string, args ...any) (*types.Transaction, error) {
	if c.bound == nil {
		return nil, errors.New("contract not configured")
	}
	opts, e := bind.NewKeyedTransactorWithChainID(key, new(big.Int).SetUint64(c.Config.ChainID))
	if e != nil {
		return nil, e
	}
	opts.Context = ctx
	opts.Value = value
	opts.GasLimit = gasLimit
	opts.NoSend = true
	return c.bound.Transact(opts, method, args...)
}
func (c *Client) Wait(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
	// Public-chain finality takes many blocks; avoid polling a shared RPC at
	// the local development rate. This changes polling, not confirmation rules.
	interval := 12 * time.Second
	if c.Config.Development {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		r, e := c.RPC.TransactionReceipt(ctx, tx.Hash())
		if e != nil && !errors.Is(e, ethereum.NotFound) {
			return nil, e
		}
		if e == nil {
			if r.Status != types.ReceiptStatusSuccessful {
				return nil, fmt.Errorf("transaction reverted: %s", tx.Hash())
			}
			h, e := c.FinalHeader(ctx)
			if e != nil {
				return nil, e
			}
			if h.Number.Cmp(r.BlockNumber) >= 0 {
				canonical, e := c.RPC.HeaderByNumber(ctx, r.BlockNumber)
				if e != nil {
					return nil, e
				}
				if canonical.Hash() == r.BlockHash {
					return r, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
func (c *Client) EventID(r *types.Receipt, name string) (uint64, error) {
	event, ok := ABI.Events[name]
	if !ok {
		return 0, errors.New("unknown event")
	}
	for _, l := range r.Logs {
		if l.Address == c.Config.Contract && len(l.Topics) == 2 && l.Topics[0] == event.ID {
			v := new(big.Int).SetBytes(l.Topics[1][:])
			if !v.IsUint64() {
				return 0, errors.New("ID overflow")
			}
			return v.Uint64(), nil
		}
	}
	return 0, errors.New("event absent")
}
func (c *Client) Settle(ctx context.Context, key *ecdsa.PrivateKey, tid uint64, r protocol.Receipt, margin uint64) (*types.Receipt, error) {
	if margin == 0 {
		return nil, errors.New("positive settlement confirmation margin required")
	}
	t, e := c.Trade(ctx, tid, true)
	if e != nil {
		return nil, e
	}
	if t.Status != 3 || ethcrypto.PubkeyToAddress(key.PublicKey) != t.Owner {
		return nil, errors.New("not owner or trade not ready")
	}
	if r.Commitment != protocol.Hash(t.Commitment) {
		return nil, errors.New("input commitment mismatch")
	}
	if e = protocol.VerifyReceipt(c.Domain(tid), r, t.EnclaveKey); e != nil {
		return nil, e
	}
	args := []any{new(big.Int).SetUint64(tid), [32]byte(r.Commitment), r.Ciphertext, r.Signature}
	input, e := ABI.Pack("settle", args...)
	if e != nil {
		return nil, e
	}
	gas, e := settlementGasLimit(len(input))
	if e != nil {
		return nil, e
	}
	// Keep receipt bytes local until the final, checked broadcast. Fee and
	// nonce queries do not contain calldata; remote gas estimation would.
	tx, e := c.prepare(ctx, key, nil, gas, "settle", args...)
	if e != nil {
		return nil, e
	}
	raw, e := tx.MarshalBinary()
	if e != nil {
		return nil, e
	}
	encoded := hexutil.Encode(raw)
	latest, e := c.Trade(ctx, tid, false)
	if e != nil {
		return nil, e
	}
	if latest.Status != 3 {
		return nil, errors.New("trade no longer ready")
	}
	observed := time.Now()
	h, e := c.RPC.HeaderByNumber(ctx, nil)
	if e != nil {
		return nil, e
	}
	if tx.Gas() > h.GasLimit {
		return nil, errors.New("settlement gas budget exceeds block gas limit")
	}
	// Include the header RPC's elapsed time, not just time since its response.
	// Production additionally uses the honest DO's synchronized wall clock, so
	// a stale block timestamp cannot manufacture extra time before the deadline.
	now := time.Now()
	if e = settlementBudget(h.Time, t.Deadline, margin, observed, now, c.Config.Development); e != nil {
		return nil, e
	}
	broadcastCtx, cancel := context.WithDeadline(ctx, now.Add(settlementDispatchBudget))
	defer cancel()
	if e = broadcastCtx.Err(); e != nil {
		return nil, e
	}
	// There are no fee/nonce/estimate RPCs or automatic resubmissions here.
	var hash common.Hash
	if e = c.RPC.Client().CallContext(broadcastCtx, &hash, "eth_sendRawTransaction", encoded); e != nil {
		return nil, fmt.Errorf("broadcast outcome uncertain for %s; inspect chain before retrying: %w", tx.Hash(), e)
	}
	if hash != tx.Hash() {
		return nil, errors.New("broadcast returned a different transaction hash")
	}
	return c.Wait(ctx, tx)
}

const settlementDispatchBudget = 5 * time.Second

// Conservative budget for the current TSC.settle, not a general EVM estimator.
// Fixed work (including a new balance slot) fits in 300k gas. Within 120 KiB,
// 64 gas per ABI byte covers calldata, hashing, memory/copying and the result
// log, including the calldata gas floor. TSC has no per-byte storage or loops.
// The size cap leaves room under the 128 KiB transaction-pool size limit; the
// budget stays below 2^24 gas. Revalidate against the EVM if TSC changes.
func settlementGasLimit(calldataBytes int) (uint64, error) {
	if calldataBytes <= 0 || calldataBytes > 120*1024 {
		return 0, errors.New("settlement calldata exceeds the local gas budget's 120 KiB limit")
	}
	return 300_000 + 64*uint64(calldataBytes), nil
}

func settlementBudget(blockTime, deadline, margin uint64, observed, now time.Time, development bool) error {
	elapsed := now.Sub(observed)
	if elapsed < 0 || elapsed > 30*time.Second {
		return errors.New("settlement time observation stale")
	}
	passed := uint64((elapsed + time.Second - 1) / time.Second)
	current := blockTime + passed
	if current < blockTime {
		return errors.New("settlement time overflow")
	}
	if !development {
		// Five seconds of clock tolerance is conservative in both directions.
		wall := now.Unix()
		if wall < 0 || blockTime > uint64(wall)+5 || uint64(wall) > blockTime+120 {
			return errors.New("chain head and local clock disagree")
		}
		if uint64(wall)+5 > current {
			current = uint64(wall) + 5
		}
	}
	const dispatch = uint64(settlementDispatchBudget / time.Second)
	if margin == 0 || current >= deadline || deadline-current <= dispatch || deadline-current-dispatch <= margin {
		return errors.New("insufficient settlement time margin after preparation")
	}
	return nil
}
func (c *Client) Result(ctx context.Context, tid uint64) ([]byte, error) {
	t, e := c.Trade(ctx, tid, true)
	if e != nil {
		return nil, e
	}
	if t.Status != 4 {
		return nil, errors.New("trade not finally settled")
	}
	o, e := c.Call(ctx, true, "resultBlocks", new(big.Int).SetUint64(tid))
	if e != nil {
		return nil, e
	}
	if len(o) != 1 || o[0].(*big.Int).Sign() <= 0 {
		return nil, errors.New("settled trade has no result block index")
	}
	height := o[0].(*big.Int)
	h, e := c.FinalHeader(ctx)
	if e != nil {
		return nil, e
	}
	if height.Cmp(h.Number) > 0 {
		return nil, errors.New("result block not finalized")
	}
	block, e := c.RPC.HeaderByNumber(ctx, height)
	if e != nil {
		return nil, fmt.Errorf("result history unavailable at block %s: %w", height, e)
	}
	blockHash := block.Hash()
	logs, e := c.RPC.FilterLogs(ctx, ethereum.FilterQuery{BlockHash: &blockHash, Addresses: []common.Address{c.Config.Contract}, Topics: [][]common.Hash{{ABI.Events["ResultDelivered"].ID}, {common.BigToHash(new(big.Int).SetUint64(tid))}}})
	if e != nil {
		return nil, fmt.Errorf("result history unavailable at block %s: %w", height, e)
	}
	if len(logs) != 1 {
		return nil, errors.New("settled result history missing or inconsistent; use a node retaining this block")
	}
	l := logs[0]
	if l.Removed || l.Address != c.Config.Contract || l.BlockHash != blockHash || l.BlockNumber != height.Uint64() || len(l.Topics) != 2 || l.Topics[0] != ABI.Events["ResultDelivered"].ID || l.Topics[1] != common.BigToHash(new(big.Int).SetUint64(tid)) {
		return nil, errors.New("result event identity mismatch")
	}
	out, e := ABI.Events["ResultDelivered"].Inputs.NonIndexed().Unpack(logs[0].Data)
	if e != nil {
		return nil, e
	}
	return out[0].([]byte), nil
}
