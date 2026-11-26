// Package admission automates sampling and cryptographic checks, NOT business review.
package admission

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

type Description struct {
	Version   string `json:"version"`
	Source    string `json:"source"`
	Batch     string `json:"batch"`
	Format    string `json:"format"`
	Records   uint64 `json:"records"`
	Summary   string `json:"summary"`
	Selection string `json:"selection"`
}
type Application struct {
	Owner       common.Address  `json:"owner"`
	Description Description     `json:"description"`
	Policy      protocol.Policy `json:"policy"`
	Commitment  protocol.Hash   `json:"commitment"`
}
type Challenge struct {
	AID     uint64   `json:"aid"`
	Indices []uint64 `json:"indices"`
}
type Response struct {
	AID     uint64                  `json:"aid"`
	Samples []protocol.SampleRecord `json:"samples"`
}

func (a Application) Validate() error {
	if a.Owner == (common.Address{}) || a.Description.Records == 0 || a.Description.Version == "" || a.Description.Source == "" || a.Description.Batch == "" || a.Description.Format == "" || a.Commitment == (protocol.Hash{}) {
		return errors.New("incomplete application")
	}
	return a.Policy.Validate()
}
func Open(ctx context.Context, c *chain.Client, key *ecdsa.PrivateKey, a Application, batch protocol.Hash) (uint64, error) {
	id, _, e := OpenWithReceipt(ctx, c, key, a, batch)
	return id, e
}

// OpenWithReceipt exposes the actual chain receipt for experimental accounting.
func OpenWithReceipt(ctx context.Context, c *chain.Client, key *ecdsa.PrivateKey, a Application, batch protocol.Hash) (uint64, *types.Receipt, error) {
	if e := a.Validate(); e != nil {
		return 0, nil, e
	}
	dh, e := protocol.JSONHash(a.Description)
	if e != nil {
		return 0, nil, e
	}
	ph, e := protocol.JSONHash(a.Policy)
	if e != nil {
		return 0, nil, e
	}
	v := protocol.H([]byte(a.Description.Version))
	r, e := c.Send(ctx, key, nil, "openAudit", a.Owner, [32]byte(batch), [32]byte(v), [32]byte(dh), [32]byte(ph), a.Description.Records, [32]byte(a.Commitment), a.Policy.AuditDeadline, a.Policy.MaxChallenges)
	if e != nil {
		return 0, nil, e
	}
	id, e := c.EventID(r, "AuditOpened")
	return id, r, e
}
func Check(ctx context.Context, c *chain.Client, id uint64, a Application) (chain.Audit, error) {
	if e := a.Validate(); e != nil {
		return chain.Audit{}, e
	}
	record, e := c.Audit(ctx, id, true)
	if e != nil {
		return record, e
	}
	dh, e := protocol.JSONHash(a.Description)
	if e != nil {
		return record, e
	}
	ph, e := protocol.JSONHash(a.Policy)
	if e != nil {
		return record, e
	}
	if record.Owner != a.Owner || record.Description != dh || record.Policy != ph || record.Records != a.Description.Records || record.Commitment != a.Commitment || record.Deadline != a.Policy.AuditDeadline || record.Version != protocol.H([]byte(a.Description.Version)) {
		return record, errors.New("application differs from chain registration")
	}
	return record, nil
}

type savedChallenge struct {
	ChainID     uint64         `json:"chain_id"`
	Contract    common.Address `json:"contract"`
	CodeHash    common.Hash    `json:"code_hash"`
	Application protocol.Hash  `json:"application_hash"`
	Challenge   Challenge      `json:"challenge"`
}

// stateDir belongs to RA and must not be exposed to DO. Persist before sending
// fixChallenge; every retry uses the same candidate, including ambiguous sends.
func CreateChallenge(ctx context.Context, c *chain.Client, key *ecdsa.PrivateKey, id uint64, a Application, stateDir string) (Challenge, error) {
	ch, _, e := CreateChallengeWithReceipt(ctx, c, key, id, a, stateDir)
	return ch, e
}

// A recovered, already fixed challenge returns a nil receipt: it did not send
// another transaction and must not be counted as a new on-chain operation.
func CreateChallengeWithReceipt(ctx context.Context, c *chain.Client, key *ecdsa.PrivateKey, id uint64, a Application, stateDir string) (Challenge, *types.Receipt, error) {
	if stateDir == "" {
		return Challenge{}, nil, errors.New("private RA state directory required")
	}
	record, e := Check(ctx, c, id, a)
	if e != nil {
		return Challenge{}, nil, e
	}
	if record.Status != 1 && record.Status != 2 {
		return Challenge{}, nil, errors.New("audit is terminal or missing")
	}
	m, e := protocol.SampleSize(record.Records, a.Policy.Rho, a.Policy.Epsilon)
	if e != nil {
		return Challenge{}, nil, e
	}
	appHash, e := protocol.JSONHash(a)
	if e != nil {
		return Challenge{}, nil, e
	}
	path := filepath.Join(stateDir, fmt.Sprintf("%d-%s-%s-%d.json", c.Config.ChainID, c.Config.Contract.Hex(), c.Config.CodeHash.Hex(), id))
	var saved savedChallenge
	e = localio.ReadJSON(path, &saved)
	if errors.Is(e, os.ErrNotExist) {
		if record.Status != 1 {
			return Challenge{}, nil, errors.New("fixed challenge has no local recovery record")
		}
		indices, err := protocol.Sample(record.Records, m, nil)
		if err != nil {
			return Challenge{}, nil, err
		}
		saved = savedChallenge{c.Config.ChainID, c.Config.Contract, c.Config.CodeHash, appHash, Challenge{id, indices}}
		if e = localio.WriteJSON(path, saved); errors.Is(e, os.ErrExist) {
			// A concurrent invocation won the atomic create. Use its candidate.
			e = localio.ReadJSON(path, &saved)
		}
	}
	if e != nil {
		return Challenge{}, nil, e
	}
	ch := saved.Challenge
	if saved.ChainID != c.Config.ChainID || saved.Contract != c.Config.Contract || saved.CodeHash != c.Config.CodeHash || saved.Application != appHash || ch.AID != id || uint64(len(ch.Indices)) != m {
		return Challenge{}, nil, errors.New("challenge recovery binding mismatch")
	}
	h, e := protocol.ChallengeHash(ch.Indices)
	if e != nil || ch.Indices[len(ch.Indices)-1] > record.Records {
		return Challenge{}, nil, errors.New("invalid saved challenge")
	}
	if e = localio.Sync(path); e != nil {
		return Challenge{}, nil, e
	}
	if record.Status == 2 {
		if record.Challenge != h {
			return Challenge{}, nil, errors.New("saved challenge differs from chain")
		}
		return ch, nil, nil
	}
	// If this call returns an uncertain outcome, the durable candidate remains.
	receipt, e := c.Send(ctx, key, nil, "fixChallenge", new(big.Int).SetUint64(id), [32]byte(h))
	if e != nil {
		return Challenge{}, nil, e
	}
	return ch, receipt, nil
}
func CheckChallenge(ctx context.Context, c *chain.Client, a Application, ch Challenge) (chain.Audit, error) {
	record, e := Check(ctx, c, ch.AID, a)
	if e != nil {
		return record, e
	}
	h, e := protocol.ChallengeHash(ch.Indices)
	if e != nil {
		return record, e
	}
	m, e := protocol.SampleSize(record.Records, a.Policy.Rho, a.Policy.Epsilon)
	if e != nil {
		return record, e
	}
	if record.Status != 2 || record.Challenge != h || uint64(len(ch.Indices)) != m || ch.Indices[len(ch.Indices)-1] > record.Records {
		return record, errors.New("challenge mismatch or audit inactive")
	}
	return record, nil
}
func Respond(ctx context.Context, c *chain.Client, key *ecdsa.PrivateKey, a Application, ch Challenge, d protocol.Dataset) (Response, error) {
	snapshot, e := protocol.NewSnapshot(d)
	if e != nil {
		return Response{}, e
	}
	return RespondWithSnapshot(ctx, c, key, a, ch, snapshot)
}

// RespondWithSnapshot retains all application/chain/identity checks while
// allowing successive audit applications to reuse the DO's local proof tree.
func RespondWithSnapshot(ctx context.Context, c *chain.Client, key *ecdsa.PrivateKey, a Application, ch Challenge, snapshot *protocol.Snapshot) (Response, error) {
	if key == nil {
		return Response{}, errors.New("data owner key required")
	}
	if ethcrypto.PubkeyToAddress(key.PublicKey) != a.Owner {
		return Response{}, errors.New("not data owner")
	}
	if _, e := CheckChallenge(ctx, c, a, ch); e != nil {
		return Response{}, e
	}
	// Timely receipt of materials is an off-chain RA decision, not a chain claim.
	if snapshot.Count() != a.Description.Records || snapshot.Commitment() != a.Commitment {
		return Response{}, errors.New("local dataset differs from application")
	}
	samples, e := snapshot.Respond(ch.Indices)
	return Response{ch.AID, samples}, e
}
func CheckResponse(ctx context.Context, c *chain.Client, a Application, ch Challenge, r Response) error {
	record, e := CheckChallenge(ctx, c, a, ch)
	if e != nil {
		return e
	}
	if r.AID != ch.AID {
		return errors.New("response application mismatch")
	}
	return protocol.VerifySamples(a.Commitment, record.Records, ch.Indices, r.Samples)
}
