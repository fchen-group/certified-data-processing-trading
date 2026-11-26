package experiment

// This driver measures gas, not protocol latency. Only this experimental path
// advances at inclusion; the production role clients still require finality.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
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
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

type GasTransaction struct {
	Round   int            `json:"round"`
	Method  string         `json:"method"`
	Raw     hexutil.Bytes  `json:"signed_transaction"`
	Receipt *types.Receipt `json:"receipt"`
}
type GasAudit struct {
	Round              int                 `json:"round"`
	AID                uint64              `json:"aid"`
	DID                uint64              `json:"did"`
	Challenge          admission.Challenge `json:"challenge"`
	ResponseHash       protocol.Hash       `json:"response_hash"`
	VerifiedSamples    int                 `json:"verified_samples"`
	CumulativeDistinct int                 `json:"cumulative_distinct_records"`
}
type GasEvent struct {
	Type    string         `json:"type"`
	Round   int            `json:"round,omitempty"`
	Method  string         `json:"method,omitempty"`
	Hash    common.Hash    `json:"hash,omitempty"`
	Raw     hexutil.Bytes  `json:"signed_transaction,omitempty"`
	Receipt *types.Receipt `json:"receipt,omitempty"`
	Audit   *GasAudit      `json:"audit,omitempty"`
}

// GasSender journals signed public transactions BEFORE broadcast. A failed or
// ambiguous submission stops the run; this driver never retries transactions.
type GasSender struct {
	Client       *chain.Client
	Key          *ecdsa.PrivateKey
	Emit         func(GasEvent) error
	MaxCost      *big.Int
	Transactions []GasTransaction
	reserved     big.Int
	next         *uint64
}

func (s *GasSender) Options(ctx context.Context) (*bind.TransactOpts, error) {
	if s.Key == nil || s.Emit == nil || s.MaxCost == nil || s.MaxCost.Sign() <= 0 {
		return nil, errors.New("key, durable journal and positive test-ETH cost cap required")
	}
	if !s.Client.Config.Development && s.Client.Config.ChainID != 11155111 {
		return nil, errors.New("gas driver only supports Sepolia or local development")
	}
	addr := ethcrypto.PubkeyToAddress(s.Key.PublicKey)
	latest, err := waitGasNonce(ctx, s.Client, addr, s.next)
	if err != nil {
		return nil, err
	}
	opts, err := bind.NewKeyedTransactorWithChainID(s.Key, new(big.Int).SetUint64(s.Client.Config.ChainID))
	if err != nil {
		return nil, err
	}
	opts.Context, opts.NoSend, opts.Nonce = ctx, true, new(big.Int).SetUint64(latest)
	return opts, nil
}

// Public RPC latest/pending views can briefly lag an already observed receipt.
// Retry only these READS, with a bounded deadline; never retry a broadcast.
func waitGasNonce(ctx context.Context, c *chain.Client, actor common.Address, next *uint64) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	interval := 4 * time.Second
	if c.Config.Development {
		interval = 20 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		var latest uint64
		err := gasRead(ctx, func(inner context.Context) error { var e error; latest, e = c.RPC.NonceAt(inner, actor, nil); return e })
		if err != nil {
			return 0, err
		}
		var pending uint64
		err = gasRead(ctx, func(inner context.Context) error {
			var e error
			pending, e = c.RPC.PendingNonceAt(inner, actor)
			return e
		})
		if err != nil {
			return 0, err
		}
		if next == nil {
			if latest != pending {
				return 0, fmt.Errorf("unexpected initial nonce: latest=%d pending=%d", latest, pending)
			}
			return latest, nil
		}
		if latest > *next || pending > *next {
			return 0, fmt.Errorf("unexpected account activity: latest=%d pending=%d expected=%d", latest, pending, *next)
		}
		if latest == *next && pending == *next {
			return latest, nil
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("nonce views did not converge: latest=%d pending=%d expected=%d: %w", latest, pending, *next, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s *GasSender) Broadcast(ctx context.Context, round int, method string, tx *types.Transaction) (*types.Receipt, error) {
	if s.Emit == nil || s.MaxCost == nil {
		return nil, errors.New("missing journal or budget")
	}
	total := new(big.Int).Add(&s.reserved, tx.Cost())
	if total.Cmp(s.MaxCost) > 0 {
		return nil, errors.New("maximum cumulative transaction cost exceeds test-ETH budget")
	}
	var balance *big.Int
	err := gasRead(ctx, func(inner context.Context) error {
		var e error
		balance, e = s.Client.RPC.BalanceAt(inner, ethcrypto.PubkeyToAddress(s.Key.PublicKey), nil)
		return e
	})
	if err != nil {
		return nil, err
	}
	if balance.Cmp(tx.Cost()) < 0 {
		return nil, errors.New("insufficient test ETH")
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err = s.Emit(GasEvent{Type: "prepared", Round: round, Method: method, Hash: tx.Hash(), Raw: raw}); err != nil {
		return nil, err
	}
	s.reserved.Set(total)
	if err = s.Client.RPC.SendTransaction(ctx, tx); err != nil {
		return nil, fmt.Errorf("broadcast uncertain for %s; do not automatically resubmit: %w", tx.Hash(), err)
	}
	r, err := waitGasInclusion(ctx, s.Client, tx.Hash())
	if err != nil {
		return nil, err
	}
	// Keep a reverted receipt as evidence, but never advance or count it as success.
	if err = s.Emit(GasEvent{Type: "included", Round: round, Method: method, Hash: tx.Hash(), Receipt: r}); err != nil {
		return nil, err
	}
	s.Transactions = append(s.Transactions, GasTransaction{round, method, raw, r})
	if r.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("transaction reverted: %s", tx.Hash())
	}
	next := tx.Nonce() + 1
	s.next = &next
	return r, nil
}
func (s *GasSender) Call(ctx context.Context, round int, method string, args ...any) (*types.Receipt, error) {
	opts, err := s.Options(ctx)
	if err != nil {
		return nil, err
	}
	c := s.Client
	// Explicit headroom skips gas estimation against a potentially stale latest
	// state. gasUsed is still taken from the actual receipt, never this limit.
	limits := map[string]uint64{"openAudit": 2_000_000, "fixChallenge": 400_000, "decideAudit": 800_000}
	limit, ok := limits[method]
	if !ok {
		return nil, errors.New("unsupported admission gas operation")
	}
	opts.GasLimit = limit
	bound := bind.NewBoundContract(c.Config.Contract, chain.ABI, c.RPC, c.RPC, c.RPC)
	tx, err := bound.Transact(opts, method, args...)
	if err != nil {
		return nil, err
	}
	return s.Broadcast(ctx, round, method, tx)
}

// A load-balanced RPC can expose a receipt before another backend knows its
// block. Only idempotent reads are retried; semantic mismatches still fail.
func gasRead(ctx context.Context, read func(context.Context) error) error {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		err := read(bounded)
		if err == nil {
			return nil
		}
		var netErr net.Error
		message := strings.ToLower(err.Error())
		temporary := errors.Is(err, ethereum.NotFound) || errors.As(err, &netErr) || strings.Contains(message, "header not found") || strings.Contains(message, "header for hash not found") || strings.Contains(message, "block not found") || (strings.Contains(message, "historical state ") && strings.Contains(message, " is not available")) || strings.Contains(err.Error(), "429 Too Many Requests") || strings.Contains(err.Error(), "502 Bad Gateway") || strings.Contains(err.Error(), "503 Service Unavailable")
		if !temporary {
			return err
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-bounded.Done():
			timer.Stop()
			return fmt.Errorf("RPC read did not recover: %w", err)
		case <-timer.C:
		}
	}
}
func gasHeader(ctx context.Context, node *ethclient.Client, height *big.Int) (*types.Header, error) {
	var h *types.Header
	err := gasRead(ctx, func(inner context.Context) error { var e error; h, e = node.HeaderByNumber(inner, height); return e })
	return h, err
}

func waitGasInclusion(ctx context.Context, c *chain.Client, hash common.Hash) (*types.Receipt, error) {
	interval := 4 * time.Second
	if c.Config.Development {
		interval = 20 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		var r *types.Receipt
		err := gasRead(ctx, func(inner context.Context) error {
			var e error
			r, e = c.RPC.TransactionReceipt(inner, hash)
			// A pending transaction normally has no receipt yet. Let the
			// inclusion poller handle it, rather than the RPC-error backoff.
			if errors.Is(e, ethereum.NotFound) {
				r = nil
				return nil
			}
			return e
		})
		if err != nil {
			return nil, err
		}
		if r != nil {
			if r.BlockNumber == nil || !r.BlockNumber.IsUint64() {
				return nil, errors.New("invalid receipt height")
			}
			h, e := gasHeader(ctx, c.RPC, r.BlockNumber)
			if e != nil {
				return nil, e
			}
			if r.TxHash != hash || h.Hash() != r.BlockHash {
				return nil, errors.New("receipt not in canonical block; stop gas trajectory")
			}
			return r, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func gasCall(ctx context.Context, node *ethclient.Client, contract common.Address, height *big.Int, method string, args ...any) ([]any, []byte, error) {
	input, err := chain.ABI.Pack(method, args...)
	if err != nil {
		return nil, nil, err
	}
	var raw []byte
	err = gasRead(ctx, func(inner context.Context) error {
		var e error
		raw, e = node.CallContract(inner, ethereum.CallMsg{To: &contract, Data: input}, height)
		return e
	})
	if err != nil {
		return nil, nil, err
	}
	out, err := chain.ABI.Unpack(method, raw)
	return out, raw, err
}
func checkGasAudit(ctx context.Context, node *ethclient.Client, contract common.Address, height *big.Int, aid uint64, a admission.Application, status uint8, challenge protocol.Hash) (chain.Audit, error) {
	out, _, err := gasCall(ctx, node, contract, height, "getAudit", new(big.Int).SetUint64(aid))
	if err != nil {
		return chain.Audit{}, err
	}
	if len(out) != 1 {
		return chain.Audit{}, errors.New("invalid audit response")
	}
	r := *abi.ConvertType(out[0], new(chain.Audit)).(*chain.Audit)
	dh, err := protocol.JSONHash(a.Description)
	if err != nil {
		return r, err
	}
	ph, err := protocol.JSONHash(a.Policy)
	if err != nil {
		return r, err
	}
	if r.Owner != a.Owner || r.Batch != protocol.H([]byte(a.Description.Batch)) || r.Version != protocol.H([]byte(a.Description.Version)) || r.Description != dh || r.Policy != ph || r.Records != a.Description.Records || r.Commitment != a.Commitment || r.Deadline != a.Policy.AuditDeadline || r.Status != status || r.Challenge != challenge {
		return r, errors.New("registered application, challenge or audit state mismatch")
	}
	return r, nil
}
func gasBudgetKey(a admission.Application) common.Hash {
	b := make([]byte, 64)
	copy(b[12:32], a.Owner[:])
	h := protocol.H([]byte(a.Description.Batch))
	copy(b[32:], h[:])
	return ethcrypto.Keccak256Hash(b)
}
func gasOpenArgs(a admission.Application) []any {
	dh, _ := protocol.JSONHash(a.Description)
	ph, _ := protocol.JSONHash(a.Policy)
	return []any{a.Owner, [32]byte(protocol.H([]byte(a.Description.Batch))), [32]byte(protocol.H([]byte(a.Description.Version))), [32]byte(dh), [32]byte(ph), a.Description.Records, [32]byte(a.Commitment), a.Policy.AuditDeadline, a.Policy.MaxChallenges}
}

// RunAdmissionGas keeps one snapshot throughout, generates genuine random
// challenges and verifies all sampled membership proofs. Business approval is
// an explicit fixture. No output is claimed finalized by this function.
func RunAdmissionGas(ctx context.Context, s *GasSender, owner *ecdsa.PrivateKey, cfg AdmissionConfig, snapshot *protocol.Snapshot) ([]GasAudit, error) {
	a, c := cfg.Application, s.Client
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if !cfg.AcceptFixture || cfg.Audits <= 0 || uint64(cfg.Audits) > a.Policy.MaxChallenges || cfg.StateDir == "" || owner == nil || ethcrypto.PubkeyToAddress(owner.PublicKey) != a.Owner || snapshot.Count() != a.Description.Records || snapshot.Commitment() != a.Commitment {
		return nil, errors.New("invalid explicit fixture, owner, audit count or snapshot")
	}
	if c.Config.Contract == (common.Address{}) || s.Key == nil {
		return nil, errors.New("dedicated contract and RA required")
	}
	actor := ethcrypto.PubkeyToAddress(s.Key.PublicKey)
	var height *big.Int
	if len(s.Transactions) > 0 {
		height = s.Transactions[len(s.Transactions)-1].Receipt.BlockNumber
	} else {
		h, e := gasHeader(ctx, c.RPC, nil)
		if e != nil {
			return nil, e
		}
		height = h.Number
	}
	out, _, err := gasCall(ctx, c.RPC, c.Config.Contract, height, "auditor")
	if err != nil {
		return nil, err
	}
	if out[0].(common.Address) != actor {
		return nil, errors.New("auditor mismatch")
	}
	for _, name := range []string{"auditCount", "dataCount", "tradeCount"} {
		out, _, err = gasCall(ctx, c.RPC, c.Config.Contract, height, name)
		if err != nil {
			return nil, err
		}
		if out[0].(*big.Int).Sign() != 0 {
			return nil, errors.New("gas measurement requires fresh isolated contract")
		}
	}
	m, err := protocol.SampleSize(a.Description.Records, a.Policy.Rho, a.Policy.Epsilon)
	if err != nil {
		return nil, err
	}
	seen := map[uint64]bool{}
	results := []GasAudit{}
	for round := 1; round <= cfg.Audits; round++ {
		if time.Now().Unix() >= int64(a.Policy.MaterialDeadline) {
			return results, errors.New("material deadline elapsed")
		}
		r, err := s.Call(ctx, round, "openAudit", gasOpenArgs(a)...)
		if err != nil {
			return results, err
		}
		aid, err := c.EventID(r, "AuditOpened")
		if err != nil {
			return results, err
		}
		if aid != uint64(round) {
			return results, errors.New("unexpected application sequence")
		}
		if _, err = checkGasAudit(ctx, c.RPC, c.Config.Contract, r.BlockNumber, aid, a, 1, protocol.Hash{}); err != nil {
			return results, err
		}
		indices, err := protocol.Sample(a.Description.Records, m, nil)
		if err != nil {
			return results, err
		}
		ch := admission.Challenge{AID: aid, Indices: indices}
		// Private candidate is durable before fixation; the CLI never resumes sends.
		if err = localio.WriteJSON(filepath.Join(cfg.StateDir, fmt.Sprintf("challenge-%03d.json", round)), ch); err != nil {
			return results, err
		}
		digest, err := protocol.ChallengeHash(indices)
		if err != nil {
			return results, err
		}
		fixedReceipt, err := s.Call(ctx, round, "fixChallenge", new(big.Int).SetUint64(aid), [32]byte(digest))
		if err != nil {
			return results, err
		}
		if _, err = checkGasAudit(ctx, c.RPC, c.Config.Contract, fixedReceipt.BlockNumber, aid, a, 2, digest); err != nil {
			return results, err
		}
		samples, err := snapshot.Respond(indices)
		if err != nil {
			return results, err
		}
		response := admission.Response{AID: aid, Samples: samples}
		wire, err := json.Marshal(response)
		if err != nil {
			return results, err
		}
		var received admission.Response
		if err = protocol.StrictJSON(wire, &received); err != nil {
			return results, err
		}
		if received.AID != aid || time.Now().Unix() >= int64(a.Policy.MaterialDeadline) {
			return results, errors.New("late or mismatched response")
		}
		if err = protocol.VerifySamples(a.Commitment, a.Description.Records, indices, received.Samples); err != nil {
			return results, err
		}
		if err = localio.WriteJSON(filepath.Join(cfg.StateDir, fmt.Sprintf("response-%03d.json", round)), received); err != nil {
			return results, err
		}
		decisionReceipt, err := s.Call(ctx, round, "decideAudit", new(big.Int).SetUint64(aid), true)
		if err != nil {
			return results, err
		}
		closed, err := checkGasAudit(ctx, c.RPC, c.Config.Contract, decisionReceipt.BlockNumber, aid, a, 3, digest)
		if err != nil {
			return results, err
		}
		if closed.Did.Cmp(new(big.Int).SetUint64(aid)) != 0 {
			return results, errors.New("certificate ID mismatch")
		}
		cert, _, err := gasCall(ctx, c.RPC, c.Config.Contract, decisionReceipt.BlockNumber, "certificate", closed.Did)
		if err != nil {
			return results, err
		}
		budget, _, err := gasCall(ctx, c.RPC, c.Config.Contract, decisionReceipt.BlockNumber, "budgets", gasBudgetKey(a))
		if err != nil {
			return results, err
		}
		if cert[0].(*big.Int).Uint64() != aid || budget[0].(uint64) != a.Policy.MaxChallenges || budget[1].(uint64) != uint64(round) {
			return results, errors.New("certificate or cumulative challenge budget mismatch")
		}
		for _, i := range indices {
			seen[i] = true
		}
		audit := GasAudit{Round: round, AID: aid, DID: aid, Challenge: ch, ResponseHash: protocol.H(wire), VerifiedSamples: len(received.Samples), CumulativeDistinct: len(seen)}
		results = append(results, audit)
		if err = s.Emit(GasEvent{Type: "audit-included", Round: round, Audit: &audit}); err != nil {
			return results, err
		}
	}
	return results, nil
}

var ErrGasNotFinalized = errors.New("gas trajectory not yet finalized")

type GasFinalVerification struct {
	VerifiedUTC   time.Time   `json:"verified_utc"`
	AnchorNumber  uint64      `json:"anchor_number"`
	AnchorHash    common.Hash `json:"anchor_hash"`
	Transactions  int         `json:"transactions"`
	Audits        int         `json:"audits"`
	GasPerAudit   []uint64    `json:"gas_per_audit"`
	DeploymentGas uint64      `json:"deployment_gas"`
	TotalFeeWei   string      `json:"total_fee_wei"`
}

// VerifyAdmissionGas checks both providers at the SAME finalized canonical
// anchor. Every included receipt, signed transaction and expected call/state
// must match; a reorg is rejected rather than silently rewriting observations.
// For integration tests only, development=true uses the common latest anchor.
func VerifyAdmissionGas(ctx context.Context, c *chain.Client, other *ethclient.Client, a admission.Application, actor common.Address, txs []GasTransaction, audits []GasAudit, creationCode []byte) (*GasFinalVerification, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if len(audits) == 0 || len(txs) != 1+3*len(audits) || uint64(len(audits)) > a.Policy.MaxChallenges {
		return nil, errors.New("incomplete gas trajectory")
	}
	nodes := []*ethclient.Client{c.RPC, other}
	tag := big.NewInt(int64(rpc.FinalizedBlockNumber))
	if c.Config.Development {
		tag = nil
	}
	var anchor *big.Int
	for _, n := range nodes {
		id, err := n.ChainID(ctx)
		if err != nil {
			return nil, err
		}
		if id.Cmp(new(big.Int).SetUint64(c.Config.ChainID)) != 0 {
			return nil, errors.New("verification chain mismatch")
		}
		h, err := gasHeader(ctx, n, tag)
		if err != nil {
			return nil, err
		}
		if anchor == nil || h.Number.Cmp(anchor) < 0 {
			anchor = new(big.Int).Set(h.Number)
		}
	}
	for _, x := range txs {
		if x.Receipt == nil || x.Receipt.BlockNumber == nil {
			return nil, errors.New("missing recorded receipt")
		}
		if x.Receipt.BlockNumber.Cmp(anchor) > 0 {
			return nil, ErrGasNotFinalized
		}
	}
	h1, err := gasHeader(ctx, nodes[0], anchor)
	if err != nil {
		return nil, err
	}
	h2, err := gasHeader(ctx, nodes[1], anchor)
	if err != nil {
		return nil, err
	}
	if h1.Hash() != h2.Hash() {
		return nil, errors.New("providers disagree on finalized anchor")
	}
	result := &GasFinalVerification{VerifiedUTC: time.Now().UTC(), AnchorNumber: anchor.Uint64(), AnchorHash: h1.Hash(), Transactions: len(txs), Audits: len(audits), GasPerAudit: make([]uint64, len(audits))}
	totalFee := new(big.Int)
	var lastNonce uint64
	seenHashes := map[common.Hash]bool{}
	constructor, err := chain.ABI.Pack("", actor)
	if err != nil {
		return nil, err
	}
	for i, x := range txs {
		var tx types.Transaction
		if err = tx.UnmarshalBinary(x.Raw); err != nil {
			return nil, err
		}
		sender, err := types.Sender(types.LatestSignerForChainID(new(big.Int).SetUint64(c.Config.ChainID)), &tx)
		if err != nil {
			return nil, err
		}
		if sender != actor || tx.Value().Sign() != 0 || tx.ChainId().Cmp(new(big.Int).SetUint64(c.Config.ChainID)) != 0 || seenHashes[tx.Hash()] || (i > 0 && tx.Nonce() != lastNonce+1) {
			return nil, errors.New("transaction sender, chain, value, uniqueness or nonce mismatch")
		}
		seenHashes[tx.Hash()] = true
		lastNonce = tx.Nonce()
		var expected []byte
		if i == 0 {
			if x.Round != 0 || x.Method != "deploy" || tx.To() != nil || ethcrypto.CreateAddress(actor, tx.Nonce()) != c.Config.Contract || len(creationCode) == 0 {
				return nil, errors.New("deployment identity mismatch")
			}
			expected = append(append([]byte{}, creationCode...), constructor...)
		} else {
			round := (i-1)/3 + 1
			phase := (i - 1) % 3
			g := audits[round-1]
			if x.Round != round || g.Round != round || g.AID != uint64(round) || g.DID != uint64(round) || g.Challenge.AID != g.AID || tx.To() == nil || *tx.To() != c.Config.Contract {
				return nil, errors.New("audit transaction association mismatch")
			}
			methods := []string{"openAudit", "fixChallenge", "decideAudit"}
			if x.Method != methods[phase] {
				return nil, errors.New("operation ordering mismatch")
			}
			ch, err := protocol.ChallengeHash(g.Challenge.Indices)
			if err != nil {
				return nil, err
			}
			switch phase {
			case 0:
				expected, err = chain.ABI.Pack(x.Method, gasOpenArgs(a)...)
			case 1:
				expected, err = chain.ABI.Pack(x.Method, new(big.Int).SetUint64(g.AID), [32]byte(ch))
			case 2:
				expected, err = chain.ABI.Pack(x.Method, new(big.Int).SetUint64(g.AID), true)
			}
			if err != nil {
				return nil, err
			}
		}
		if x.Receipt.TxHash != tx.Hash() || x.Receipt.Status != types.ReceiptStatusSuccessful || x.Receipt.GasUsed == 0 {
			return nil, errors.New("recorded receipt identity or status mismatch")
		}
		if !bytes.Equal(tx.Data(), expected) {
			return nil, errors.New("signed calldata differs from expected experiment")
		}
		for _, node := range nodes {
			actual, pending, err := node.TransactionByHash(ctx, tx.Hash())
			if err != nil {
				return nil, err
			}
			actualRaw, e := actual.MarshalBinary()
			if e != nil {
				return nil, e
			}
			if pending || !bytes.Equal(actualRaw, x.Raw) {
				return nil, errors.New("canonical signed transaction mismatch")
			}
			r, err := node.TransactionReceipt(ctx, tx.Hash())
			if err != nil {
				return nil, err
			}
			if r.Status != 1 || r.TxHash != tx.Hash() || r.BlockNumber == nil || r.BlockNumber.Cmp(anchor) > 0 || r.BlockHash != x.Receipt.BlockHash || r.BlockNumber.Cmp(x.Receipt.BlockNumber) != 0 || r.GasUsed != x.Receipt.GasUsed || r.TransactionIndex != x.Receipt.TransactionIndex || r.EffectiveGasPrice == nil || x.Receipt.EffectiveGasPrice == nil || r.EffectiveGasPrice.Cmp(x.Receipt.EffectiveGasPrice) != 0 {
				return nil, errors.New("final receipt differs from included observation")
			}
			h, err := gasHeader(ctx, node, r.BlockNumber)
			if err != nil {
				return nil, err
			}
			if h.Hash() != r.BlockHash {
				return nil, errors.New("receipt block no longer canonical")
			}
			if i == 0 && r.ContractAddress != c.Config.Contract {
				return nil, errors.New("deployment receipt address mismatch")
			}
		}
		if i == 0 {
			result.DeploymentGas = x.Receipt.GasUsed
		} else {
			result.GasPerAudit[(i-1)/3] += x.Receipt.GasUsed
		}
		totalFee.Add(totalFee, new(big.Int).Mul(new(big.Int).SetUint64(x.Receipt.GasUsed), x.Receipt.EffectiveGasPrice))
	}
	for _, node := range nodes {
		code, err := node.CodeAt(ctx, c.Config.Contract, anchor)
		if err != nil {
			return nil, err
		}
		if len(code) == 0 || ethcrypto.Keccak256Hash(code) != c.Config.CodeHash {
			return nil, errors.New("finalized contract code mismatch")
		}
	}
	checkedCall := func(method string, args ...any) ([]any, error) {
		one, raw, err := gasCall(ctx, nodes[0], c.Config.Contract, anchor, method, args...)
		if err != nil {
			return nil, err
		}
		_, raw2, err := gasCall(ctx, nodes[1], c.Config.Contract, anchor, method, args...)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(raw, raw2) {
			return nil, errors.New("providers disagree on finalized contract state")
		}
		return one, nil
	}
	out, err := checkedCall("auditor")
	if err != nil {
		return nil, err
	}
	if out[0].(common.Address) != actor {
		return nil, errors.New("final auditor mismatch")
	}
	for _, name := range []string{"auditCount", "dataCount", "tradeCount"} {
		out, err = checkedCall(name)
		if err != nil {
			return nil, err
		}
		want := int64(len(audits))
		if name == "tradeCount" {
			want = 0
		}
		if out[0].(*big.Int).Cmp(big.NewInt(want)) != 0 {
			return nil, errors.New("final counter mismatch")
		}
	}
	out, err = checkedCall("budgets", gasBudgetKey(a))
	if err != nil {
		return nil, err
	}
	if out[0].(uint64) != a.Policy.MaxChallenges || out[1].(uint64) != uint64(len(audits)) {
		return nil, errors.New("final challenge budget mismatch")
	}
	m, err := protocol.SampleSize(a.Description.Records, a.Policy.Rho, a.Policy.Epsilon)
	if err != nil {
		return nil, err
	}
	seen := map[uint64]bool{}
	for _, g := range audits {
		if uint64(len(g.Challenge.Indices)) != m || g.VerifiedSamples != int(m) || g.Challenge.Indices[len(g.Challenge.Indices)-1] > a.Description.Records {
			return nil, errors.New("sample count or range mismatch")
		}
		digest, err := protocol.ChallengeHash(g.Challenge.Indices)
		if err != nil {
			return nil, err
		}
		r, err := checkGasAudit(ctx, nodes[0], c.Config.Contract, anchor, g.AID, a, 3, digest)
		if err != nil {
			return nil, err
		}
		if r.Did.Cmp(new(big.Int).SetUint64(g.DID)) != 0 {
			return nil, errors.New("final did mismatch")
		}
		if _, err = checkedCall("getAudit", new(big.Int).SetUint64(g.AID)); err != nil {
			return nil, err
		}
		out, err = checkedCall("certificate", new(big.Int).SetUint64(g.DID))
		if err != nil {
			return nil, err
		}
		if out[0].(*big.Int).Cmp(new(big.Int).SetUint64(g.AID)) != 0 {
			return nil, errors.New("final certificate mismatch")
		}
		for _, i := range g.Challenge.Indices {
			seen[i] = true
		}
		if g.CumulativeDistinct != len(seen) {
			return nil, errors.New("cumulative sample count mismatch")
		}
	}
	result.TotalFeeWei = totalFee.String()
	return result, nil
}
