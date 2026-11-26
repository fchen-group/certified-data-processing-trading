//go:build integration

package experiment

// These are local rule-compatibility checks, not performance measurements or
// claims about fork activation. They run the actual TSC artifact through Geth's
// full transaction state transition, including intrinsic gas and calldata floors.
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/gasestimator"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"certified-data-processing-trading/pkg/chain"
	"certified-data-processing-trading/pkg/protocol"
)

type tradeForkEngine struct{ consensus.Engine }

func (tradeForkEngine) Author(h *types.Header) (common.Address, error) { return h.Coinbase, nil }

type tradeForkChain struct {
	consensus.ChainHeaderReader // TSC does not use historical BLOCKHASH queries.
	cfg                         *params.ChainConfig
	header                      *types.Header
}

func (c *tradeForkChain) Config() *params.ChainConfig  { return c.cfg }
func (c *tradeForkChain) CurrentHeader() *types.Header { return c.header }
func (c *tradeForkChain) Engine() consensus.Engine     { return tradeForkEngine{} }

func forkMessage(s *state.StateDB, from common.Address, to *common.Address, data []byte, value *big.Int, gas uint64) *core.Message {
	return &core.Message{From: from, To: to, Nonce: s.GetNonce(from), Data: data, Value: uint256.MustFromBig(value), GasLimit: gas,
		GasPrice: new(uint256.Int), GasFeeCap: new(uint256.Int), GasTipCap: new(uint256.Int)}
}

func forkApply(c *tradeForkChain, s *state.StateDB, msg *core.Message) (*core.ExecutionResult, []*types.Log, error) {
	hash := ethcrypto.Keccak256Hash(msg.From.Bytes(), new(big.Int).SetUint64(msg.Nonce).Bytes(), msg.Data)
	s.SetTxContext(hash, 0, 0)
	evm := vm.NewEVM(core.NewEVMBlockContext(c.header, c, nil), s, c.cfg, vm.Config{NoBaseFee: true})
	defer evm.Release()
	result, err := core.ApplyMessage(evm, msg, core.NewGasPool(c.header.GasLimit))
	if err != nil {
		return result, nil, err
	}
	logs := s.GetLogs(hash, c.header.Number.Uint64(), c.header.Hash(), c.header.Time)
	s.Finalise(c.cfg.Rules(c.header.Number, true, c.header.Time))
	return result, logs, nil
}

func TestTradeGasForkCompatibility(t *testing.T) {
	for _, fork := range []string{"Prague", "Amsterdam"} {
		t.Run(fork, func(t *testing.T) {
			cfg := *params.AllDevChainProtocolChanges
			cfg.OsakaTime, cfg.BogotaTime, cfg.AmsterdamTime = nil, nil, nil
			if fork == "Amsterdam" {
				zero := uint64(0)
				cfg.OsakaTime, cfg.BogotaTime, cfg.AmsterdamTime = &zero, &zero, &zero
			}
			c := &tradeForkChain{cfg: &cfg, header: &types.Header{Number: big.NewInt(1), Time: 1000, GasLimit: 60_000_000, Difficulty: new(big.Int), BaseFee: new(big.Int)}}
			s, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			if err != nil {
				t.Fatal(err)
			}
			ra, owner, buyer := common.HexToAddress("0x1001"), common.HexToAddress("0x1002"), common.HexToAddress("0x1003")
			for _, a := range []common.Address{ra, owner, buyer} {
				s.SetBalance(a, uint256.NewInt(1_000_000_000_000_000_000), tracing.BalanceChangeUnspecified)
			}
			s.Finalise(cfg.Rules(c.header.Number, true, c.header.Time))
			runCall := func(from common.Address, to *common.Address, input []byte, value *big.Int, gas uint64) (*core.ExecutionResult, []*types.Log) {
				msg := forkMessage(s, from, to, input, value, gas)
				if gas == 0 {
					estimate, _, err := gasestimator.Estimate(context.Background(), msg, &gasestimator.Options{Config: &cfg, Chain: c, Header: c.header, State: s}, 1<<24)
					if err != nil {
						t.Fatalf("estimate: %v", err)
					}
					msg.GasLimit, err = chain.OrdinaryGasLimit(estimate, c.header.GasLimit)
					if err != nil {
						t.Fatal(err)
					}
				}
				res, logs, err := forkApply(c, s, msg)
				if err != nil || res.Err != nil {
					t.Fatalf("transaction failed: result=%+v error=%v", res, err)
				}
				c.header.Number = new(big.Int).Add(c.header.Number, big.NewInt(1))
				c.header.Time++
				return res, logs
			}
			pack := func(method string, args ...any) []byte {
				b, err := chain.ABI.Pack(method, args...)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			artifact, err := os.ReadFile("../../contracts/out/TSC.sol/TSC.json")
			if err != nil {
				t.Fatal("build the current TSC artifact with forge build first: ", err)
			}
			var compiled struct{ Bytecode struct{ Object string } }
			if err := json.Unmarshal(artifact, &compiled); err != nil {
				t.Fatal(err)
			}
			creation := hexutil.MustDecode("0x" + strings.TrimPrefix(compiled.Bytecode.Object, "0x"))
			contract := ethcrypto.CreateAddress(ra, s.GetNonce(ra))
			runCall(ra, nil, append(creation, pack("", ra)...), new(big.Int), 0)
			if len(s.GetCode(contract)) == 0 {
				t.Fatal("contract was not deployed")
			}
			binding := [32]byte{1}
			runCall(ra, &contract, pack("openAudit", owner, binding, binding, binding, binding, uint64(1000), binding, uint64(100000), uint64(10)), new(big.Int), 0)
			runCall(ra, &contract, pack("fixChallenge", big.NewInt(1), binding), new(big.Int), 0)
			runCall(ra, &contract, pack("decideAudit", big.NewInt(1), true), new(big.Int), 0)
			key, err := ethcrypto.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			resultKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			price := big.NewInt(1_000_000_000_000)
			run := &TradeGasRun{Plan: TradeGasPlan{PriceWei: price.String()}, Owner: owner, Buyer: buyer, ReceiptKey: ethcrypto.PubkeyToAddress(key.PublicKey)}
			// All six D2 lengths plus the Ready -> Refunded branch.
			for j, size := range []int{128, 512, 1024, 4096, 16384, 65536, 0} {
				trial := &TradeGasTrial{TID: uint64(j + 1)}
				id := new(big.Int).SetUint64(trial.TID)
				call := func(label string, from common.Address, value *big.Int, gas uint64, args ...any) *core.ExecutionResult {
					method := strings.Split(label, "/")[0]
					res, logs := runCall(from, &contract, pack(method, args...), value, gas)
					if err := checkTradeLogs(contract, run, trial, label, logs); err != nil {
						t.Fatalf("%s: %v", label, err)
					}
					transfers := 0
					for _, l := range logs {
						if l.Address != contract {
							transfers++
						}
					}
					want := 0
					if fork == "Amsterdam" && (method == "deposit" || method == "withdraw" || method == "timeoutRefund") {
						want = 1
					}
					if transfers != want {
						t.Fatalf("%s: system logs=%d, want %d", label, transfers, want)
					}
					return res
				}
				registerArgs := []any{big.NewInt(1), binding, binding, buyer, price, uint64(3600)}
				if j < 2 {
					probe, _, err := forkApply(c, s.Copy(), forkMessage(s, owner, &contract, pack("registerTrade", registerArgs...), new(big.Int), 800000))
					if err != nil {
						t.Fatal(err)
					}
					if fork == "Amsterdam" && !errors.Is(probe.Err, vm.ErrOutOfGas) {
						t.Fatalf("expected old 800000 limit to fail: %v", probe.Err)
					}
					if fork == "Prague" && probe.Err != nil {
						t.Fatal(probe.Err)
					}
				}
				registered := call("registerTrade", owner, new(big.Int), 0, registerArgs...)
				if j < 2 {
					t.Logf("registration %d full transaction gasUsed=%d", j+1, registered.UsedGas)
				}
				buyerBefore, ownerBefore := s.GetBalance(buyer).Clone(), s.GetBalance(owner).Clone()
				trial.Deadline = c.header.Time + 3600
				call("deposit", buyer, price, 0, id)
				call("confirmKey/DO", owner, new(big.Int), 0, id, run.ReceiptKey)
				call("confirmKey/DB", buyer, new(big.Int), 0, id, run.ReceiptKey)
				if size == 0 {
					c.header.Time = trial.Deadline + 1
					call("timeoutRefund", buyer, new(big.Int), 0, id)
					if s.GetBalance(buyer).Cmp(buyerBefore) != 0 {
						t.Fatal("refund did not restore buyer funds")
					}
				} else {
					domain := protocol.Domain{ChainID: cfg.ChainID.Uint64(), Contract: contract, TID: trial.TID}
					plain := bytes.Repeat([]byte{0x61}, size)
					trial.Ciphertext, err = protocol.EncryptResult(resultKey.PublicKey().Bytes(), plain, domain)
					if err != nil {
						t.Fatal(err)
					}
					trial.Signature, err = protocol.Sign(key, protocol.ReceiptDigest(domain, protocol.Hash(binding), trial.Ciphertext))
					if err != nil {
						t.Fatal(err)
					}
					args := []any{id, binding, []byte(trial.Ciphertext), []byte(trial.Signature)}
					input := pack("settle", args...)
					floor, err := core.FloorDataGas(cfg.Rules(c.header.Number, true, c.header.Time), owner, &contract, new(uint256.Int), input, nil)
					if err != nil {
						t.Fatal(err)
					}
					res := call("settle", owner, new(big.Int), 300000+64*uint64(len(input)), args...)
					// The crossover depends on the fork's execution and data costs.
					// The largest fixture binds to the floor under both rule sets.
					if res.UsedGas < floor || (size == 65536 && res.UsedGas != floor) {
						t.Fatalf("size=%d: gas=%d floor=%d", size, res.UsedGas, floor)
					}
					t.Logf("plaintext=%d calldata=%d gasUsed=%d floor=%d", size, len(input), res.UsedGas, floor)
					call("withdraw", owner, new(big.Int), 0)
					if s.GetBalance(owner).Cmp(new(uint256.Int).Add(ownerBefore, uint256.MustFromBig(price))) != 0 || s.GetBalance(buyer).Cmp(new(uint256.Int).Sub(buyerBefore, uint256.MustFromBig(price))) != 0 {
						t.Fatal("payment did not transfer the price to owner")
					}
				}
				if !s.GetBalance(contract).IsZero() {
					t.Fatal("contract funds not restored")
				}
			}
		})
	}
}
