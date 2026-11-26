package experiment

// This is a contract microbenchmark. It deliberately does not emulate SGX or
// change the finality/settlement policy of the production clients.
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
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
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/protocol"
)

type TradeGasFixture struct {
	Name      string        `json:"name"`
	Plaintext hexutil.Bytes `json:"plaintext"`
	Source    string        `json:"source"`
}
type TradeGasPlan struct {
	DID            uint64            `json:"did"`
	Commitment     protocol.Hash     `json:"commitment"`
	Source         protocol.Hash     `json:"source"`
	Measurement    protocol.Hash     `json:"measurement"`
	PriceWei       string            `json:"price_wei"`
	Duration       uint64            `json:"duration_seconds"`
	RefundDuration uint64            `json:"refund_duration_seconds"`
	Repeats        int               `json:"repeats"`
	Refunds        int               `json:"refunds"`
	Sizes          []int             `json:"plaintext_sizes"`
	Fixtures       []TradeGasFixture `json:"fixtures"`
}

func (p TradeGasPlan) Validate() error {
	price, ok := new(big.Int).SetString(p.PriceWei, 10)
	if !ok || price.Sign() <= 0 || price.BitLen() > 256 || p.DID == 0 || p.Duration == 0 || p.RefundDuration == 0 || p.Repeats <= 0 || p.Refunds <= 0 || p.Commitment == (protocol.Hash{}) || p.Source == (protocol.Hash{}) || p.Measurement == (protocol.Hash{}) {
		return errors.New("invalid trade gas plan")
	}
	if len(p.Fixtures) != 2 || p.Fixtures[0].Name != "T1" || p.Fixtures[1].Name != "T2" {
		return errors.New("T1 and T2 fixtures required in that order")
	}
	for _, f := range p.Fixtures {
		if len(f.Plaintext) == 0 || len(f.Plaintext) > 65536 || f.Source == "" {
			return errors.New("invalid result fixture")
		}
	}
	want := []int{128, 512, 1024, 4096, 16384, 65536}
	if !equalJSON(p.Sizes, want) {
		return errors.New("D2 must cover all six frozen plaintext sizes")
	}
	return nil
}

type TradeGasTrial struct {
	Group      string         `json:"group"` // preparation, D1/T1, D1/T2, D2/<size>, refund
	Repeat     int            `json:"repeat"`
	TID        uint64         `json:"tid"`
	Deadline   uint64         `json:"deadline"`
	Ciphertext hexutil.Bytes  `json:"ciphertext,omitempty"`
	Signature  hexutil.Bytes  `json:"signature,omitempty"`
	Steps      []TradeGasStep `json:"steps"`
}
type TradeGasState struct {
	Block       uint64      `json:"block"`
	BlockHash   common.Hash `json:"block_hash"`
	Trade       chain.Trade `json:"trade"`
	Credit      string      `json:"owner_credit_wei"`
	ResultBlock uint64      `json:"result_block"`
}
type TradeGasStep struct {
	Tx    GasTransaction `json:"transaction"`
	State TradeGasState  `json:"state_after"`
}
type TradeGasRun struct {
	Plan            TradeGasPlan    `json:"plan"`
	Owner           common.Address  `json:"owner"`
	Buyer           common.Address  `json:"buyer"`
	ReceiptKey      common.Address  `json:"receipt_key"`
	ResultPublicKey hexutil.Bytes   `json:"result_public_key"`
	InitialBlock    uint64          `json:"initial_block"`
	InitialHash     common.Hash     `json:"initial_hash"`
	InitialCounter  uint64          `json:"initial_counter"`
	Trials          []TradeGasTrial `json:"trials"`
}

func equalJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func tradeUint(ctx context.Context, n *ethclient.Client, contract common.Address, h *big.Int, method string, args ...any) (*big.Int, error) {
	v, _, e := gasCall(ctx, n, contract, h, method, args...)
	if e != nil {
		return nil, e
	}
	return v[0].(*big.Int), nil
}
func tradeState(ctx context.Context, n *ethclient.Client, contract common.Address, h *big.Int, tid uint64, owner common.Address) (TradeGasState, error) {
	var s TradeGasState
	header, e := gasHeader(ctx, n, h)
	if e != nil {
		return s, e
	}
	s.Block, s.BlockHash = header.Number.Uint64(), header.Hash()
	v, _, e := gasCall(ctx, n, contract, h, "getTrade", new(big.Int).SetUint64(tid))
	if e != nil {
		return s, e
	}
	s.Trade = *abi.ConvertType(v[0], new(chain.Trade)).(*chain.Trade)
	credit, e := tradeUint(ctx, n, contract, h, "balances", owner)
	if e != nil {
		return s, e
	}
	s.Credit = credit.String()
	rb, e := tradeUint(ctx, n, contract, h, "resultBlocks", new(big.Int).SetUint64(tid))
	if e != nil {
		return s, e
	}
	s.ResultBlock = rb.Uint64()
	return s, nil
}
func checkTradeCertificate(ctx context.Context, n *ethclient.Client, c *chain.Client, r *TradeGasRun, h *big.Int) error {
	aid, e := tradeUint(ctx, n, c.Config.Contract, h, "certificate", new(big.Int).SetUint64(r.Plan.DID))
	if e != nil {
		return e
	}
	v, _, e := gasCall(ctx, n, c.Config.Contract, h, "getAudit", aid)
	if e != nil {
		return e
	}
	a := *abi.ConvertType(v[0], new(chain.Audit)).(*chain.Audit)
	if a.Status != 3 || a.Owner != r.Owner || a.Did == nil || a.Did.Uint64() != r.Plan.DID || a.Commitment != [32]byte(r.Plan.Commitment) {
		return errors.New("certified fixture/owner mismatch")
	}
	return nil
}

// Deterministic public payload, encrypted independently for every new tid.
func tradePayload(p TradeGasPlan, group string) ([]byte, error) {
	for _, f := range p.Fixtures {
		if group == "D1/"+f.Name {
			return f.Plaintext, nil
		}
	}
	for _, n := range p.Sizes {
		if group == fmt.Sprintf("D2/%d", n) {
			out := make([]byte, n)
			for i := 0; i < n; i += 32 {
				var ctr [8]byte
				binary.BigEndian.PutUint64(ctr[:], uint64(i/32))
				s := sha256.Sum256(append([]byte("WORK2_D2_PAYLOAD_V1"), ctr[:]...))
				copy(out[i:], s[:])
			}
			return out, nil
		}
	}
	return nil, errors.New("unknown result group")
}
func tradeMethods(group string) []string {
	if group == "preparation" {
		return []string{"registerTrade"}
	}
	if group == "refund" {
		return []string{"registerTrade", "deposit", "confirmKey/DO", "confirmKey/DB", "timeoutRefund"}
	}
	return []string{"registerTrade", "deposit", "confirmKey/DO", "confirmKey/DB", "settle", "withdraw"}
}
func tradeCallSpec(r *TradeGasRun, t *TradeGasTrial, step int) (string, common.Address, *big.Int, []any, error) {
	methods := tradeMethods(t.Group)
	if step >= len(methods) {
		return "", common.Address{}, nil, nil, errors.New("extra operation")
	}
	m := methods[step]
	actor := r.Owner
	value := new(big.Int)
	price, _ := new(big.Int).SetString(r.Plan.PriceWei, 10)
	id := new(big.Int).SetUint64(t.TID)
	var args []any
	switch m {
	case "registerTrade":
		duration := r.Plan.Duration
		if t.Group == "refund" {
			duration = r.Plan.RefundDuration
		}
		args = []any{new(big.Int).SetUint64(r.Plan.DID), [32]byte(r.Plan.Source), [32]byte(r.Plan.Measurement), r.Buyer, price, duration}
	case "deposit":
		actor = r.Buyer
		value.Set(price)
		args = []any{id}
	case "confirmKey/DO", "confirmKey/DB":
		if m == "confirmKey/DB" {
			actor = r.Buyer
		}
		m = "confirmKey"
		args = []any{id, r.ReceiptKey}
	case "settle":
		args = []any{id, [32]byte(r.Plan.Commitment), []byte(t.Ciphertext), []byte(t.Signature)}
	case "withdraw":
	case "timeoutRefund":
		actor = r.Buyer
		args = []any{id}
	}
	return m, actor, value, args, nil
}

// tradeGasBlock identifies the state already checked by the driver, rather than
// the possibly lagging default state of an RPC backend.
type tradeGasBlock struct {
	Number uint64
	Hash   common.Hash
}

func (b tradeGasBlock) header(ctx context.Context, node *ethclient.Client) (*types.Header, error) {
	h, err := gasHeader(ctx, node, new(big.Int).SetUint64(b.Number))
	if err != nil {
		return nil, err
	}
	if h.Hash() != b.Hash {
		return nil, errors.New("gas estimation prerequisite block changed")
	}
	return h, nil
}

func tradeGasLimit(ctx context.Context, node *ethclient.Client, msg ethereum.CallMsg, block tradeGasBlock) (uint64, error) {
	if _, err := block.header(ctx, node); err != nil {
		return 0, err
	}
	var estimate uint64
	err := gasRead(ctx, func(ctx context.Context) error {
		var err error
		estimate, err = node.EstimateGasAtBlockHash(ctx, msg, block.Hash)
		return err
	})
	if err != nil {
		return 0, err
	}
	// Also reject a reorganization observed while the estimate was in flight.
	h, err := block.header(ctx, node)
	if err != nil {
		return 0, err
	}
	return chain.OrdinaryGasLimit(estimate, h.GasLimit)
}

func tradeSend(ctx context.Context, s *GasSender, block tradeGasBlock, round int, label, method string, value *big.Int, args ...any) (*types.Receipt, error) {
	opts, e := s.Options(ctx)
	if e != nil {
		return nil, e
	}
	opts.Value = value
	input, e := chain.ABI.Pack(method, args...)
	if e != nil {
		return nil, e
	}
	switch method {
	case "registerTrade", "deposit", "confirmKey", "withdraw", "timeoutRefund":
		// These calls contain public transaction terms only. Estimate on the
		// target chain at the checked prerequisite state. Missing blocks can
		// be retried by gasRead; contract reverts must still stop the run.
		opts.GasLimit, e = tradeGasLimit(ctx, s.Client.RPC, ethereum.CallMsg{From: opts.From, To: &s.Client.Config.Contract, Value: value, Data: input}, block)
		if e != nil {
			return nil, fmt.Errorf("estimate %s: %w", method, e)
		}
	case "settle":
		// Same full-calldata cap and resource bound as the production Settle path.
		if len(input) > 120*1024 {
			return nil, errors.New("settlement exceeds 120 KiB calldata limit")
		}
		opts.GasLimit = 300000 + 64*uint64(len(input))
	default:
		return nil, errors.New("unsupported trade gas operation")
	}
	bound := bind.NewBoundContract(s.Client.Config.Contract, chain.ABI, s.Client.RPC, s.Client.RPC, s.Client.RPC)
	tx, e := bound.Transact(opts, method, args...)
	if e != nil {
		return nil, e
	}
	return s.Broadcast(ctx, round, label, tx)
}

// RunTradeGas stops on the first failure. Each signed transaction is journaled
// by GasSender before broadcast; each checked state is emitted before advancing.
func RunTradeGas(ctx context.Context, owner, buyer *GasSender, p TradeGasPlan, receiptKey *ecdsa.PrivateKey, resultPK []byte, emit func(*TradeGasRun) error) (*TradeGasRun, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if owner == nil || buyer == nil || owner.Key == nil || buyer.Key == nil || owner.Client != buyer.Client || receiptKey == nil || emit == nil || len(resultPK) != 32 {
		return nil, errors.New("invalid driver inputs")
	}
	c := owner.Client
	r := &TradeGasRun{Plan: p, Owner: ethcrypto.PubkeyToAddress(owner.Key.PublicKey), Buyer: ethcrypto.PubkeyToAddress(buyer.Key.PublicKey), ReceiptKey: ethcrypto.PubkeyToAddress(receiptKey.PublicKey), ResultPublicKey: bytes.Clone(resultPK)}
	if r.Owner == r.Buyer {
		return r, errors.New("distinct roles required")
	}
	h, e := gasHeader(ctx, c.RPC, nil)
	if e != nil {
		return r, e
	}
	r.InitialBlock, r.InitialHash = h.Number.Uint64(), h.Hash()
	block := tradeGasBlock{Number: r.InitialBlock, Hash: r.InitialHash}
	if e = checkTradeCertificate(ctx, c.RPC, c, r, h.Number); e != nil {
		return r, e
	}
	counter, e := tradeUint(ctx, c.RPC, c.Config.Contract, h.Number, "tradeCount")
	if e != nil {
		return r, e
	}
	if !counter.IsUint64() {
		return r, errors.New("counter overflow")
	}
	r.InitialCounter = counter.Uint64()
	credit, e := tradeUint(ctx, c.RPC, c.Config.Contract, h.Number, "balances", r.Owner)
	if e != nil {
		return r, e
	}
	if credit.Sign() != 0 {
		return r, errors.New("owner credit must initially be zero")
	}
	if e = emit(r); e != nil {
		return r, e
	}
	var cases []TradeGasTrial
	if r.InitialCounter == 0 {
		cases = append(cases, TradeGasTrial{Group: "preparation"})
	}
	for _, f := range p.Fixtures {
		for i := 1; i <= p.Repeats; i++ {
			cases = append(cases, TradeGasTrial{Group: "D1/" + f.Name, Repeat: i})
		}
	}
	for _, n := range p.Sizes {
		for i := 1; i <= p.Repeats; i++ {
			cases = append(cases, TradeGasTrial{Group: fmt.Sprintf("D2/%d", n), Repeat: i})
		}
	}
	for i := 1; i <= p.Refunds; i++ {
		cases = append(cases, TradeGasTrial{Group: "refund", Repeat: i})
	}
	for _, trial := range cases {
		r.Trials = append(r.Trials, trial)
		t := &r.Trials[len(r.Trials)-1]
		for step, label := range tradeMethods(t.Group) {
			if label == "settle" {
				plain, err := tradePayload(p, t.Group)
				if err != nil {
					return r, err
				}
				t.Ciphertext, e = protocol.EncryptResult(resultPK, plain, c.Domain(t.TID))
				if e != nil {
					return r, e
				}
				t.Signature, e = protocol.Sign(receiptKey, protocol.ReceiptDigest(c.Domain(t.TID), p.Commitment, t.Ciphertext))
				if e != nil {
					return r, e
				}
			}
			if label == "timeoutRefund" {
				if _, e = block.header(ctx, c.RPC); e != nil {
					return r, e
				}
				h, err := waitTradeDeadline(ctx, c, t.Deadline)
				if err != nil {
					return r, err
				}
				if _, e = block.header(ctx, c.RPC); e != nil {
					return r, e
				}
				// Refund eligibility depends on time. Recheck the prerequisite
				// state at the observed post-deadline block before estimating.
				state, err := tradeState(ctx, c.RPC, c.Config.Contract, h.Number, t.TID, r.Owner)
				if err != nil {
					return r, err
				}
				previous := t.Steps[len(t.Steps)-1].State
				if state.Block < block.Number || state.BlockHash != h.Hash() || !equalJSON(state.Trade, previous.Trade) || state.Credit != previous.Credit || state.ResultBlock != previous.ResultBlock {
					return r, errors.New("refund prerequisite state changed")
				}
				block = tradeGasBlock{Number: state.Block, Hash: state.BlockHash}
			}
			method, actor, value, args, err := tradeCallSpec(r, t, step)
			if err != nil {
				return r, err
			}
			s := owner
			if actor == r.Buyer {
				s = buyer
			}
			receipt, err := tradeSend(ctx, s, block, len(r.Trials), label, method, value, args...)
			if err != nil {
				return r, err
			}
			if step == 0 {
				t.TID, e = c.EventID(receipt, "TradeRegistered")
				if e != nil {
					return r, e
				}
				if t.TID != r.InitialCounter+uint64(len(r.Trials)) {
					return r, errors.New("unexpected trade counter activity")
				}
			}
			state, err := tradeState(ctx, c.RPC, c.Config.Contract, receipt.BlockNumber, t.TID, r.Owner)
			if err != nil {
				return r, err
			}
			if label == "deposit" {
				t.Deadline = state.Trade.Deadline
			}
			x := TradeGasStep{Tx: s.Transactions[len(s.Transactions)-1], State: state}
			t.Steps = append(t.Steps, x)
			if e = checkTradeStep(ctx, c.RPC, c, r, t, step); e != nil {
				return r, e
			}
			if e = emit(r); e != nil {
				return r, e
			}
			block = tradeGasBlock{Number: state.Block, Hash: state.BlockHash}
		}
	}
	return r, nil
}
func waitTradeDeadline(ctx context.Context, c *chain.Client, deadline uint64) (*types.Header, error) {
	if c.Config.Development {
		h, e := gasHeader(ctx, c.RPC, nil)
		if e != nil {
			return nil, e
		}
		if h.Time > deadline {
			return h, nil
		}
		var out any
		if e := c.RPC.Client().CallContext(ctx, &out, "evm_setNextBlockTimestamp", deadline+1); e != nil {
			return nil, e
		}
		if e := c.RPC.Client().CallContext(ctx, &out, "evm_mine"); e != nil {
			return nil, e
		}
	}
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		h, e := gasHeader(ctx, c.RPC, nil)
		if e != nil {
			return nil, e
		}
		if h.Time > deadline {
			return h, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func checkTradeStep(ctx context.Context, node *ethclient.Client, c *chain.Client, r *TradeGasRun, t *TradeGasTrial, i int) error {
	x := t.Steps[i]
	h := x.Tx.Receipt.BlockNumber
	s, e := tradeState(ctx, node, c.Config.Contract, h, t.TID, r.Owner)
	if e != nil {
		return e
	}
	if !equalJSON(s, x.State) || s.BlockHash != x.Tx.Receipt.BlockHash {
		return errors.New("recorded state differs from canonical receipt-block state")
	}
	price, _ := new(big.Int).SetString(r.Plan.PriceWei, 10)
	duration := r.Plan.Duration
	if t.Group == "refund" {
		duration = r.Plan.RefundDuration
	}
	want := chain.Trade{Did: new(big.Int).SetUint64(r.Plan.DID), Owner: r.Owner, Buyer: r.Buyer, Source: [32]byte(r.Plan.Source), Measurement: [32]byte(r.Plan.Measurement), Commitment: [32]byte(r.Plan.Commitment), Price: price, Duration: duration, Status: 1}
	if i >= 1 {
		fundHeader, e := gasHeader(ctx, node, t.Steps[1].Tx.Receipt.BlockNumber)
		if e != nil {
			return e
		}
		if t.Deadline != fundHeader.Time+duration {
			return errors.New("funding deadline mismatch")
		}
		want.Deadline = t.Deadline
		want.Status = 2
	}
	if i >= 2 {
		want.OwnerKey = r.ReceiptKey
	}
	if i >= 3 {
		want.BuyerKey = r.ReceiptKey
		want.EnclaveKey = r.ReceiptKey
		want.Status = 3
	}
	credit := "0"
	rb := uint64(0)
	if i >= 4 {
		if t.Group == "refund" {
			want.Status = 5
		} else {
			want.Status = 4
			rb = t.Steps[4].Tx.Receipt.BlockNumber.Uint64()
			if i == 4 {
				credit = price.String()
			}
		}
	}
	if !equalJSON(s.Trade, want) || s.Credit != credit || s.ResultBlock != rb {
		return fmt.Errorf("unexpected state after %s (tid %d)", x.Tx.Method, t.TID)
	}
	header, e := gasHeader(ctx, node, h)
	if e != nil {
		return e
	}
	if i >= 2 && i <= 4 && t.Group != "refund" && header.Time > t.Deadline {
		return errors.New("normal call past deadline")
	}
	if x.Tx.Method == "timeoutRefund" && header.Time <= t.Deadline {
		return errors.New("refund before actual chain deadline")
	}
	if e := checkTradeLogs(c.Config.Contract, r, t, x.Tx.Method, x.Tx.Receipt.Logs); e != nil {
		return e
	}
	// Equivalent credit state is checked BEFORE settlement as well as after it.
	parent := new(big.Int).Sub(h, big.NewInt(1))
	beforeContract, e := node.BalanceAt(ctx, c.Config.Contract, parent)
	if e != nil {
		return e
	}
	afterContract, e := node.BalanceAt(ctx, c.Config.Contract, h)
	if e != nil {
		return e
	}
	expectedContract := new(big.Int).Set(beforeContract)
	switch x.Tx.Method {
	case "deposit":
		expectedContract.Add(expectedContract, price)
	case "withdraw", "timeoutRefund":
		expectedContract.Sub(expectedContract, price)
	}
	if afterContract.Cmp(expectedContract) != 0 {
		return errors.New("unexpected contract funds change")
	}
	if x.Tx.Method == "settle" {
		v, e := tradeUint(ctx, node, c.Config.Contract, parent, "balances", r.Owner)
		if e != nil {
			return e
		}
		if v.Sign() != 0 {
			return errors.New("settlement started with nonzero credit")
		}
	}
	if x.Tx.Method == "withdraw" || x.Tx.Method == "timeoutRefund" {
		actor := r.Owner
		if x.Tx.Method == "timeoutRefund" {
			actor = r.Buyer
		}
		before, e := node.BalanceAt(ctx, actor, parent)
		if e != nil {
			return e
		}
		after, e := node.BalanceAt(ctx, actor, h)
		if e != nil {
			return e
		}
		fee := new(big.Int).Mul(new(big.Int).SetUint64(x.Tx.Receipt.GasUsed), x.Tx.Receipt.EffectiveGasPrice)
		expected := new(big.Int).Sub(new(big.Int).Add(before, price), fee)
		if after.Cmp(expected) != 0 {
			return errors.New("withdraw/refund did not restore actual account funds")
		}
	}
	return nil
}

// checkTradeLogs validates TSC events separately from EIP-7708 transfer logs.
// Older forks omit the latter. If present, their sender, recipient and amount
// must match this operation; arbitrary foreign logs are never ignored.
func checkTradeLogs(contract common.Address, r *TradeGasRun, t *TradeGasTrial, method string, receiptLogs []*types.Log) error {
	price, ok := new(big.Int).SetString(r.Plan.PriceWei, 10)
	if !ok {
		return errors.New("invalid trade price")
	}
	var from, to common.Address
	switch method {
	case "deposit":
		from, to = r.Buyer, contract
	case "withdraw":
		from, to = contract, r.Owner
	case "timeoutRefund":
		from, to = contract, r.Buyer
	}
	var logs []*types.Log
	systemLogs := 0
	for _, log := range receiptLogs {
		if log == nil || log.Removed {
			return errors.New("invalid or removed operation log")
		}
		if log.Address == contract {
			logs = append(logs, log)
			continue
		}
		if log.Address != common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe") || from == (common.Address{}) {
			return errors.New("unexpected non-TSC operation log")
		}
		systemLogs++
		if systemLogs > 1 || len(log.Topics) != 3 ||
			log.Topics[0] != ethcrypto.Keccak256Hash([]byte("Transfer(address,address,uint256)")) ||
			log.Topics[1] != common.BytesToHash(from.Bytes()) || log.Topics[2] != common.BytesToHash(to.Bytes()) ||
			!bytes.Equal(log.Data, common.LeftPadBytes(price.Bytes(), 32)) {
			return errors.New("unexpected ETH transfer system log")
		}
	}
	// Validate the exact emitted event, including indexed identity and payload.
	var name string
	var args []any
	topic := common.BigToHash(new(big.Int).SetUint64(t.TID))
	switch method {
	case "registerTrade":
		name = "TradeRegistered"
	case "deposit":
		name = "Funded"
		args = []any{t.Deadline}
	case "confirmKey/DO":
	case "confirmKey/DB":
		name = "KeyFixed"
		args = []any{r.ReceiptKey}
	case "settle":
		name = "ResultDelivered"
		args = []any{[]byte(t.Ciphertext)}
	case "withdraw":
		name = "Withdrawn"
		topic = common.BytesToHash(r.Owner.Bytes())
		args = []any{price}
	case "timeoutRefund":
		name = "Refunded"
	default:
		return errors.New("unsupported trade gas operation")
	}
	if name == "" {
		if len(logs) != 0 {
			return errors.New("unexpected first key-confirmation event")
		}
	} else {
		data, e := chain.ABI.Events[name].Inputs.NonIndexed().Pack(args...)
		if e != nil {
			return e
		}
		if len(logs) != 1 || logs[0].Address != contract || len(logs[0].Topics) != 2 || logs[0].Topics[0] != chain.ABI.Events[name].ID || logs[0].Topics[1] != topic || !bytes.Equal(logs[0].Data, data) || logs[0].Removed {
			return errors.New("unexpected operation event")
		}
	}
	return nil
}

type TradeGasTotal struct {
	Group           string            `json:"group"`
	Repeat          int               `json:"repeat"`
	TID             uint64            `json:"tid"`
	PlaintextBytes  int               `json:"plaintext_bytes"`
	CiphertextBytes int               `json:"ciphertext_bytes"`
	CalldataBytes   int               `json:"settlement_calldata_bytes"`
	NormalGas       uint64            `json:"normal_five_call_gas"`
	OperationGas    map[string]uint64 `json:"operation_gas"`
}
type TradeGasVerification struct {
	VerifiedUTC  time.Time       `json:"verified_utc"`
	Development  bool            `json:"development"`
	AnchorNumber uint64          `json:"anchor_number"`
	AnchorHash   common.Hash     `json:"anchor_hash"`
	Transactions int             `json:"transactions"`
	Trials       []TradeGasTotal `json:"trials"`
}

// VerifyTradeGas is read-only: both RPCs must agree at a common finalized anchor.
// The development-only path uses latest; its output is not Sepolia evidence.
func VerifyTradeGas(ctx context.Context, c *chain.Client, other *ethclient.Client, r *TradeGasRun, resultSK []byte) (*TradeGasVerification, error) {
	if r == nil || other == nil {
		return nil, errors.New("missing verification input")
	}
	if e := r.Plan.Validate(); e != nil {
		return nil, e
	}
	key, e := ecdh.X25519().NewPrivateKey(resultSK)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(key.PublicKey().Bytes(), r.ResultPublicKey) || r.Owner == (common.Address{}) || r.Buyer == (common.Address{}) || r.ReceiptKey == (common.Address{}) || r.Owner == r.Buyer {
		return nil, errors.New("invalid role or result key identity")
	}
	var groups []string
	var reps []int
	add := func(g string, n int) {
		for j := 1; j <= n; j++ {
			groups = append(groups, g)
			reps = append(reps, j)
		}
	}
	if r.InitialCounter == 0 {
		groups = append(groups, "preparation")
		reps = append(reps, 0)
	}
	for _, f := range r.Plan.Fixtures {
		add("D1/"+f.Name, r.Plan.Repeats)
	}
	for _, n := range r.Plan.Sizes {
		add(fmt.Sprintf("D2/%d", n), r.Plan.Repeats)
	}
	add("refund", r.Plan.Refunds)
	if len(r.Trials) != len(groups) {
		return nil, errors.New("incomplete trade gas matrix")
	}
	nodes := []*ethclient.Client{c.RPC, other}
	tag := big.NewInt(int64(rpc.FinalizedBlockNumber))
	if c.Config.Development {
		tag = nil
	}
	var anchor *big.Int
	for _, n := range nodes {
		id, e := n.ChainID(ctx)
		if e != nil {
			return nil, e
		}
		if id.Uint64() != c.Config.ChainID {
			return nil, errors.New("chain identity mismatch")
		}
		h, e := gasHeader(ctx, n, tag)
		if e != nil {
			return nil, e
		}
		if anchor == nil || h.Number.Cmp(anchor) < 0 {
			anchor = new(big.Int).Set(h.Number)
		}
	}
	for _, trial := range r.Trials {
		for _, step := range trial.Steps {
			if step.Tx.Receipt == nil || step.Tx.Receipt.BlockNumber == nil {
				return nil, errors.New("missing receipt")
			}
			if step.Tx.Receipt.BlockNumber.Cmp(anchor) > 0 {
				return nil, ErrGasNotFinalized
			}
		}
	}
	v := &TradeGasVerification{Development: c.Config.Development, AnchorNumber: anchor.Uint64()}
	for _, n := range nodes {
		h, e := gasHeader(ctx, n, anchor)
		if e != nil {
			return nil, e
		}
		if v.AnchorHash == (common.Hash{}) {
			v.AnchorHash = h.Hash()
		}
		if v.AnchorHash != h.Hash() {
			return nil, errors.New("finalized anchor disagreement")
		}
		code, e := n.CodeAt(ctx, c.Config.Contract, anchor)
		if e != nil {
			return nil, e
		}
		if len(code) == 0 || ethcrypto.Keccak256Hash(code) != c.Config.CodeHash {
			return nil, errors.New("runtime code mismatch")
		}
		initial, e := gasHeader(ctx, n, new(big.Int).SetUint64(r.InitialBlock))
		if e != nil {
			return nil, e
		}
		if initial.Hash() != r.InitialHash {
			return nil, errors.New("initial block changed")
		}
		count, e := tradeUint(ctx, n, c.Config.Contract, initial.Number, "tradeCount")
		if e != nil {
			return nil, e
		}
		if count.Uint64() != r.InitialCounter {
			return nil, errors.New("initial counter mismatch")
		}
		if e = checkTradeCertificate(ctx, n, c, r, anchor); e != nil {
			return nil, e
		}
		count, e = tradeUint(ctx, n, c.Config.Contract, anchor, "tradeCount")
		if e != nil {
			return nil, e
		}
		if count.Uint64() != r.InitialCounter+uint64(len(groups)) {
			return nil, errors.New("final counter mismatch")
		}
	}
	var checks []func(context.Context) error
	lastNonce := map[common.Address]uint64{}
	seen := map[common.Hash]bool{}
	lastBlock := r.InitialBlock
	for j := range r.Trials {
		t := &r.Trials[j]
		if t.Group != groups[j] || t.Repeat != reps[j] || t.TID != r.InitialCounter+uint64(j+1) || len(t.Steps) != len(tradeMethods(t.Group)) {
			return nil, errors.New("incomplete or reordered trial")
		}
		total := TradeGasTotal{Group: t.Group, Repeat: t.Repeat, TID: t.TID, CiphertextBytes: len(t.Ciphertext), OperationGas: map[string]uint64{}}
		for i, x := range t.Steps {
			if x.Tx.Receipt == nil || x.Tx.Receipt.BlockNumber == nil {
				return nil, errors.New("missing receipt")
			}
			if x.Tx.Receipt.BlockNumber.Cmp(anchor) > 0 {
				return nil, ErrGasNotFinalized
			}
			var tx types.Transaction
			if e := tx.UnmarshalBinary(x.Tx.Raw); e != nil {
				return nil, e
			}
			method, actor, value, args, e := tradeCallSpec(r, t, i)
			if e != nil {
				return nil, e
			}
			expected, e := chain.ABI.Pack(method, args...)
			if e != nil {
				return nil, e
			}
			signer, e := types.Sender(types.LatestSignerForChainID(new(big.Int).SetUint64(c.Config.ChainID)), &tx)
			if e != nil {
				return nil, e
			}
			if tx.To() == nil || *tx.To() != c.Config.Contract || tx.ChainId().Cmp(new(big.Int).SetUint64(c.Config.ChainID)) != 0 || signer != actor || tx.Value().Cmp(value) != 0 || !bytes.Equal(tx.Data(), expected) || seen[tx.Hash()] || x.Tx.Round != j+1 || x.Tx.Method != tradeMethods(t.Group)[i] {
				return nil, errors.New("signed call/actor/order mismatch")
			}
			if prev, ok := lastNonce[actor]; ok && tx.Nonce() != prev+1 {
				return nil, errors.New("unexpected account nonce activity")
			}
			lastNonce[actor] = tx.Nonce()
			seen[tx.Hash()] = true
			if x.Tx.Receipt.BlockNumber.Uint64() <= lastBlock {
				return nil, errors.New("dependent calls must occupy successively observed blocks")
			}
			lastBlock = x.Tx.Receipt.BlockNumber.Uint64()
			for provider, n := range nodes {
				checks = append(checks, func(ctx context.Context) error {
					err := gasRead(ctx, func(ctx context.Context) error {
						actual, pending, e := n.TransactionByHash(ctx, tx.Hash())
						if e != nil {
							return e
						}
						raw, e := actual.MarshalBinary()
						if e != nil {
							return e
						}
						if pending || !bytes.Equal(raw, x.Tx.Raw) {
							return errors.New("canonical transaction mismatch")
						}
						receipt, e := n.TransactionReceipt(ctx, tx.Hash())
						if e != nil {
							return e
						}
						if !sameGasReceipt(receipt, x.Tx.Receipt) || receipt.Status != 1 || receipt.GasUsed == 0 || receipt.TxHash != tx.Hash() {
							return errors.New("final receipt differs from included observation")
						}
						h, e := gasHeader(ctx, n, receipt.BlockNumber)
						if e != nil {
							return e
						}
						if h.Hash() != receipt.BlockHash {
							return errors.New("receipt block changed")
						}
						if e = checkTradeStep(ctx, n, c, r, t, i); e != nil {
							return e
						}
						return nil
					})
					if err != nil {
						return fmt.Errorf("provider %d tid %d %s block %d: %w", provider+1, t.TID, x.Tx.Method, x.Tx.Receipt.BlockNumber.Uint64(), err)
					}
					return nil
				})
			}
			total.OperationGas[x.Tx.Method] = x.Tx.Receipt.GasUsed
			v.Transactions++
			if t.Group != "preparation" && t.Group != "refund" && i < 5 {
				total.NormalGas += x.Tx.Receipt.GasUsed
			}
			if method == "settle" {
				total.CalldataBytes = len(expected)
				if len(expected) > 120*1024 {
					return nil, errors.New("oversized settlement")
				}
			}
		}
		if t.Group != "preparation" && t.Group != "refund" {
			plain, e := tradePayload(r.Plan, t.Group)
			if e != nil {
				return nil, e
			}
			total.PlaintextBytes = len(plain)
			if len(t.Ciphertext) != len(plain)+48 {
				return nil, errors.New("HPKE length mismatch")
			}
			if e = protocol.VerifyReceipt(c.Domain(t.TID), protocol.Receipt{Commitment: r.Plan.Commitment, Ciphertext: t.Ciphertext, Signature: t.Signature}, r.ReceiptKey); e != nil {
				return nil, e
			}
			checks = append(checks, func(ctx context.Context) error {
				err := gasRead(ctx, func(ctx context.Context) error {
					// Use the ordinary finalized DB retrieval path, only after the batch.
					cipher, e := c.Result(ctx, t.TID)
					if e != nil {
						return e
					}
					if !bytes.Equal(cipher, t.Ciphertext) {
						return errors.New("DB retrieval differs from submitted ciphertext")
					}
					decoded, e := protocol.DecryptResult(resultSK, cipher, c.Domain(t.TID))
					if e != nil {
						return e
					}
					if !bytes.Equal(decoded, plain) {
						return errors.New("decrypted result differs from exact plaintext fixture")
					}
					return nil
				})
				if err != nil {
					return fmt.Errorf("DB result tid %d: %w", t.TID, err)
				}
				return nil
			})
		} else if len(t.Ciphertext) != 0 || len(t.Signature) != 0 {
			return nil, errors.New("unexpected result in non-settlement path")
		}
		checks = append(checks, func(ctx context.Context) error {
			err := gasRead(ctx, func(ctx context.Context) error {
				// Recheck the terminal trade and zero credit at the common anchor.
				for _, n := range nodes {
					s, e := tradeState(ctx, n, c.Config.Contract, anchor, t.TID, r.Owner)
					if e != nil {
						return e
					}
					last := t.Steps[len(t.Steps)-1].State
					if !equalJSON(s.Trade, last.Trade) || s.ResultBlock != last.ResultBlock || s.Credit != "0" {
						return errors.New("final state mismatch")
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("terminal state tid %d: %w", t.TID, err)
			}
			return nil
		})
		v.Trials = append(v.Trials, total)
	}
	if err := runTradeGasChecks(ctx, checks, 4); err != nil {
		return nil, err
	}
	v.VerifiedUTC = time.Now().UTC()
	return v, nil
}

// Only independent, idempotent checks run concurrently. Signed-call ordering
// and nonce checks above remain sequential; no verification condition is skipped.
func runTradeGasChecks(ctx context.Context, checks []func(context.Context) error, workers int) error {
	if workers < 1 {
		return errors.New("positive verifier concurrency required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	queue := make(chan func(context.Context) error)
	var wg sync.WaitGroup
	var once sync.Once
	var first error
	var mu sync.Mutex
	done := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for check := range queue {
				if ctx.Err() != nil {
					return
				}
				if err := check(ctx); err != nil {
					once.Do(func() { first = err; cancel() })
					return
				}
				mu.Lock()
				done++
				if done%32 == 0 || done == len(checks) {
					log.Printf("Read-only verification: %d/%d checks", done, len(checks))
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, check := range checks {
		select {
		case <-ctx.Done():
			break feed
		case queue <- check:
		}
	}
	close(queue)
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}

// Provider-specific optional JSON fields are not part of the comparison.
func sameGasReceipt(a, b *types.Receipt) bool {
	return a != nil && b != nil && a.BlockNumber != nil && b.BlockNumber != nil && a.BlockNumber.Cmp(b.BlockNumber) == 0 && a.BlockHash == b.BlockHash && a.TxHash == b.TxHash && a.Status == b.Status && a.GasUsed == b.GasUsed && a.CumulativeGasUsed == b.CumulativeGasUsed && a.TransactionIndex == b.TransactionIndex && a.Type == b.Type && a.ContractAddress == b.ContractAddress && a.EffectiveGasPrice != nil && b.EffectiveGasPrice != nil && a.EffectiveGasPrice.Cmp(b.EffectiveGasPrice) == 0 && equalJSON(a.Logs, b.Logs)
}
