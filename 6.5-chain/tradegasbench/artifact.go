package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"certified-data-processing-trading/pkg/chain"
)

// TSC has one immutable: the auditor address. Check the actual runtime image,
// including its metadata, rather than treating an ABI match as code provenance.
func artifactCodeHash(data []byte, auditor common.Address) (common.Hash, error) {
	var a struct {
		Runtime struct {
			Object     hexutil.Bytes `json:"object"`
			Immutables map[string][]struct {
				Start  int `json:"start"`
				Length int `json:"length"`
			} `json:"immutableReferences"`
		} `json:"deployedBytecode"`
	}
	if err := json.Unmarshal(data, &a); err != nil {
		return common.Hash{}, err
	}
	if len(a.Runtime.Object) == 0 || len(a.Runtime.Immutables) != 1 || auditor == (common.Address{}) {
		return common.Hash{}, errors.New("expected TSC runtime with one auditor immutable")
	}
	for _, refs := range a.Runtime.Immutables {
		if len(refs) == 0 {
			return common.Hash{}, errors.New("missing auditor immutable offsets")
		}
		for _, ref := range refs {
			if ref.Length != 32 || ref.Start < 0 || ref.Start > len(a.Runtime.Object)-32 {
				return common.Hash{}, errors.New("invalid auditor immutable offset")
			}
			copy(a.Runtime.Object[ref.Start:ref.Start+32], common.LeftPadBytes(auditor.Bytes(), 32))
		}
	}
	return ethcrypto.Keccak256Hash(a.Runtime.Object), nil
}

func checkArtifact(ctx context.Context, c *chain.Client, data []byte) error {
	v, err := c.Call(ctx, true, "auditor")
	if err != nil {
		return err
	}
	h, err := artifactCodeHash(data, v[0].(common.Address))
	if err != nil {
		return err
	}
	if h != c.Config.CodeHash {
		return fmt.Errorf("artifact runtime does not match pinned deployed TSC: %s", h)
	}
	return nil
}
