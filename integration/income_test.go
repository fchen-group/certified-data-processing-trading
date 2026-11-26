//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/localio"
	"certified-data-processing-trading/pkg/protocol"
)

func TestFullAdultIncomeThroughTLSAndSettlement(t *testing.T) {
	base := "../data/adult/classification/"
	input, err := os.ReadFile(base + "test.csv")
	if os.IsNotExist(err) {
		t.Skip("prepare T2 artifacts for full integration check")
	}
	if err != nil {
		t.Fatal(err)
	}
	rows, err := analyzer.ReadAdultRows(bytes.NewReader(input), 0)
	if err != nil || len(rows) != 16281 {
		t.Fatal("wrong held-out dataset", err)
	}
	var p analyzer.Parameters
	if err := localio.ReadJSON(base+"parameters.json", &p); err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Count uint64 `json:"count"`
		Above uint64 `json:"above_threshold"`
	}
	b, err := os.ReadFile(base + "reference.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &ref); err != nil {
		t.Fatal(err)
	}
	env := setupEnvironment(t, false)
	env.data, err = protocol.Prepare(rows)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := protocol.Build(env.data)
	if err != nil {
		t.Fatal(err)
	}
	env.app.Description.Format = analyzer.AdultFormat
	env.app.Description.Records = uint64(len(rows))
	env.app.Commitment = tree.Commitment()
	aid, err := admission.Open(env.ctx, env.c, env.ra, env.app, protocol.H([]byte("official-heldout-test")))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := admission.CreateChallenge(env.ctx, env.c, env.ra, aid, env.app, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	response, err := admission.Respond(env.ctx, env.c, env.owner, env.app, challenge, env.data)
	if err != nil {
		t.Fatal(err)
	}
	if err = admission.CheckResponse(env.ctx, env.c, env.app, challenge, response); err != nil {
		t.Fatal(err)
	}
	if _, err = env.c.Send(env.ctx, env.ra, nil, "decideAudit", new(big.Int).SetUint64(aid), true); err != nil {
		t.Fatal(err)
	}
	audit, err := env.c.Audit(env.ctx, aid, true)
	if err != nil {
		t.Fatal(err)
	}
	env.did = audit.Did.Uint64()
	tid, out, sk := env.executeTask(t, p, false)
	if out.Receipt.Commitment != env.app.Commitment || out.TotalNanoseconds <= 0 {
		t.Fatal("invalid execution evidence/timer")
	}
	var sum int64
	for _, ns := range out.Nanoseconds {
		if ns <= 0 {
			t.Fatal("invalid phase time")
		}
		sum += ns
	}
	if len(out.Nanoseconds) != 5 || sum > out.TotalNanoseconds {
		t.Fatal("inconsistent time boundaries")
	}
	if _, err = env.c.Settle(env.ctx, env.owner, tid, out.Receipt, 30); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := env.c.Result(env.ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := protocol.DecryptResult(sk.Bytes(), ciphertext, env.c.Domain(tid))
	if err != nil {
		t.Fatal(err)
	}
	var result analyzer.Result
	if err = protocol.StrictJSON(plaintext, &result); err != nil || result.Count != ref.Count || result.Above != ref.Above {
		t.Fatal("settled result differs from sklearn reference", result, err)
	}
	t.Logf("T2: %d complete held-out records, %d positive predictions, TLS + chain delivery validated", result.Count, result.Above)
}
