// Package experiment contains measurement drivers, not production role policy.
package experiment

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/protocol"
)

type AdmissionConfig struct {
	Application   admission.Application
	Audits        int
	StateDir      string
	AcceptFixture bool
}

type Transaction struct {
	Method      string      `json:"method"`
	Hash        common.Hash `json:"hash"`
	BlockHash   common.Hash `json:"block_hash"`
	BlockNumber uint64      `json:"block_number"`
	GasUsed     uint64      `json:"gas_used"`
	CallNS      int64       `json:"call_ns"`
}

type ChainAudit struct {
	Round              int                 `json:"round"`
	AID                uint64              `json:"aid"`
	DID                uint64              `json:"did"`
	Commitment         protocol.Hash       `json:"commitment"`
	Challenge          admission.Challenge `json:"challenge"`
	Transactions       []Transaction       `json:"transactions"`
	RespondNS          int64               `json:"respond_with_chain_checks_ns"`
	ResponseEncodeNS   int64               `json:"response_encode_ns"`
	ResponseDecodeNS   int64               `json:"response_decode_ns"`
	VerifyNS           int64               `json:"verify_with_chain_checks_ns"`
	StateCheckNS       int64               `json:"state_checks_ns"`
	FlowNS             int64               `json:"coordinator_flow_ns"`
	ReceivedAt         int64               `json:"received_at"`
	ChallengeWireBytes int                 `json:"challenge_wire_bytes"`
	ResponseWireBytes  int                 `json:"response_wire_bytes"`
	SampleRecordBytes  int                 `json:"sample_record_bytes"`
	SaltBytes          int                 `json:"salt_bytes"`
	ProofHashBytes     int                 `json:"proof_hash_bytes"`
	CumulativeDistinct int                 `json:"cumulative_distinct_records"`
	ChallengesUsed     uint64              `json:"challenges_used"`
	Verified           bool                `json:"verified"`
}

// Events are persisted between operations so a failed run retains confirmed
// transactions and the stage of an uncertain outcome. No automatic retry.
type AdmissionEvent struct {
	Type        string       `json:"type"`
	Round       int          `json:"round,omitempty"`
	Stage       string       `json:"stage,omitempty"`
	AID         uint64       `json:"aid,omitempty"`
	Error       string       `json:"error,omitempty"`
	Transaction *Transaction `json:"transaction,omitempty"`
	Audit       *ChainAudit  `json:"audit,omitempty"`
}

// RunAdmission never builds a tree: the caller supplies one retained snapshot.
// A fresh dedicated deployment isolates each statistical repetition without
// resetting a real batch's budget. All audits retain the same owner and batch.
func RunAdmission(ctx context.Context, c *chain.Client, owner, ra *ecdsa.PrivateKey, cfg AdmissionConfig, snapshot *protocol.Snapshot, emit func(AdmissionEvent) error) (err error) {
	stage, round, aid := "preflight", 0, uint64(0)
	if emit == nil {
		return errors.New("measurement event sink required")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, emit(AdmissionEvent{Type: "failure", Round: round, Stage: stage, AID: aid, Error: err.Error()}))
		}
	}()
	a := cfg.Application
	if err = a.Validate(); err != nil {
		return err
	}
	if !cfg.AcceptFixture || cfg.Audits <= 0 || uint64(cfg.Audits) > a.Policy.MaxChallenges || cfg.StateDir == "" {
		return errors.New("explicit fixture acceptance, bounded audit count and private challenge directory required")
	}
	if owner == nil || ra == nil || ethcrypto.PubkeyToAddress(owner.PublicKey) != a.Owner {
		return errors.New("owner/RA keys required and owner must match application")
	}
	if snapshot.Count() != a.Description.Records || snapshot.Commitment() != a.Commitment {
		return errors.New("retained snapshot differs from application")
	}
	if c.Config.Contract == (common.Address{}) {
		return errors.New("dedicated deployed contract required")
	}
	auditor, err := c.Call(ctx, true, "auditor")
	if err != nil {
		return err
	}
	if auditor[0].(common.Address) != ethcrypto.PubkeyToAddress(ra.PublicKey) {
		return errors.New("RA key differs from deployed auditor")
	}
	for _, field := range []string{"auditCount", "dataCount", "tradeCount"} {
		values, e := c.Call(ctx, true, field)
		if e != nil {
			return e
		}
		if values[0].(*big.Int).Sign() != 0 {
			return errors.New("measurement requires a fresh isolated TSC deployment")
		}
	}
	batch := protocol.H([]byte(a.Description.Batch))
	budgetInput := make([]byte, 64) // abi.encode(address owner, bytes32 batch)
	copy(budgetInput[12:32], a.Owner[:])
	copy(budgetInput[32:], batch[:])
	budgetKey := ethcrypto.Keccak256Hash(budgetInput)
	seen := make(map[uint64]bool)
	checkpoint := func(name string) error {
		stage = name
		return emit(AdmissionEvent{Type: "stage", Round: round, Stage: stage, AID: aid})
	}
	for round = 1; round <= cfg.Audits; round++ {
		aid = 0
		if time.Now().Unix() > int64(a.Policy.MaterialDeadline) {
			return errors.New("material submission deadline elapsed")
		}
		result := ChainAudit{Round: round, Commitment: snapshot.Commitment()}
		flowStart := time.Now()
		recordTx := func(method string, r *types.Receipt, duration time.Duration) error {
			if r == nil || r.Status != types.ReceiptStatusSuccessful || r.BlockNumber == nil || !r.BlockNumber.IsUint64() {
				return errors.New("missing successful receipt for measured chain operation")
			}
			tx := Transaction{method, r.TxHash, r.BlockHash, r.BlockNumber.Uint64(), r.GasUsed, duration.Nanoseconds()}
			result.Transactions = append(result.Transactions, tx)
			return emit(AdmissionEvent{Type: "transaction", Round: round, Stage: method, AID: aid, Transaction: &tx})
		}
		if err = checkpoint("openAudit"); err != nil {
			return err
		}
		start := time.Now()
		id, receipt, e := admission.OpenWithReceipt(ctx, c, ra, a, batch)
		duration := time.Since(start)
		if e != nil {
			return e
		}
		aid, result.AID = id, id
		if err = recordTx("openAudit", receipt, duration); err != nil {
			return err
		}
		if err = checkpoint("fixChallenge"); err != nil {
			return err
		}
		start = time.Now()
		ch, receipt, e := admission.CreateChallengeWithReceipt(ctx, c, ra, aid, a, cfg.StateDir)
		duration = time.Since(start)
		if e != nil {
			return e
		}
		result.Challenge = ch
		if err = recordTx("fixChallenge", receipt, duration); err != nil {
			return err
		}
		challengeWire, e := json.Marshal(ch)
		if e != nil {
			return e
		}
		result.ChallengeWireBytes = len(challengeWire)
		if err = checkpoint("respond-and-verify"); err != nil {
			return err
		}
		start = time.Now()
		response, e := admission.RespondWithSnapshot(ctx, c, owner, a, ch, snapshot)
		result.RespondNS = time.Since(start).Nanoseconds()
		if e != nil {
			return e
		}
		start = time.Now()
		wire, e := json.Marshal(response)
		result.ResponseEncodeNS = time.Since(start).Nanoseconds()
		if e != nil {
			return e
		}
		result.ResponseWireBytes = len(wire)
		var received admission.Response
		start = time.Now()
		e = protocol.StrictJSON(wire, &received)
		result.ResponseDecodeNS = time.Since(start).Nanoseconds()
		if e != nil {
			return e
		}
		result.ReceivedAt = time.Now().Unix()
		if result.ReceivedAt > int64(a.Policy.MaterialDeadline) {
			return errors.New("materials received after deadline")
		}
		start = time.Now()
		e = admission.CheckResponse(ctx, c, a, ch, received)
		result.VerifyNS = time.Since(start).Nanoseconds()
		if e != nil {
			return e
		}
		for _, sample := range received.Samples {
			seen[sample.Index] = true
			result.SampleRecordBytes += len(sample.Record)
			result.SaltBytes += len(sample.Salt)
			result.ProofHashBytes += len(sample.Proof.Siblings) * 32
		}
		result.CumulativeDistinct = len(seen)
		if err = checkpoint("decideAudit"); err != nil {
			return err
		}
		// Acceptance is the operator's explicit experiment fixture, not a claim
		// that cryptographic membership checks establish business authenticity.
		start = time.Now()
		receipt, e = c.Send(ctx, ra, nil, "decideAudit", new(big.Int).SetUint64(aid), true)
		duration = time.Since(start)
		if e != nil {
			return e
		}
		if err = recordTx("decideAudit", receipt, duration); err != nil {
			return err
		}
		if err = checkpoint("verify-final-state"); err != nil {
			return err
		}
		start = time.Now()
		closed, e := admission.Check(ctx, c, aid, a)
		if e != nil {
			return e
		}
		if closed.Status != 3 || closed.Batch != batch || closed.Did.Sign() <= 0 || !closed.Did.IsUint64() {
			return errors.New("audit did not reach the expected certified state")
		}
		cert, e := c.Call(ctx, true, "certificate", closed.Did)
		if e != nil {
			return e
		}
		budget, e := c.Call(ctx, true, "budgets", budgetKey)
		if e != nil {
			return e
		}
		if cert[0].(*big.Int).Cmp(new(big.Int).SetUint64(aid)) != 0 || budget[0].(uint64) != a.Policy.MaxChallenges || budget[1].(uint64) != uint64(round) {
			return fmt.Errorf("certificate association or cumulative budget mismatch at audit %d", round)
		}
		result.StateCheckNS = time.Since(start).Nanoseconds()
		result.DID, result.ChallengesUsed = closed.Did.Uint64(), uint64(round)
		result.Verified = true
		result.FlowNS = time.Since(flowStart).Nanoseconds()
		if err = emit(AdmissionEvent{Type: "audit", Round: round, AID: aid, Audit: &result}); err != nil {
			return err
		}
	}
	return emit(AdmissionEvent{Type: "complete"})
}
