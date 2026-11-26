//go:build integration

package integration

import (
	"math/big"
	"testing"

	"certified-data-processing-trading/pkg/admission"
	"certified-data-processing-trading/pkg/protocol"
)

func TestRetainedSnapshotPreservesAdmissionChecks(t *testing.T) {
	env := setup(t)
	snapshot, err := protocol.NewSnapshot(env.data)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := protocol.Prepare(env.data.Records)
	if err != nil {
		t.Fatal(err)
	}
	wrongSnapshot, err := protocol.NewSnapshot(changed)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	for i := 0; i < 2; i++ {
		aid := newAudit(t, env, "retained-snapshot")
		challenge, err := admission.CreateChallenge(env.ctx, env.c, env.ra, aid, env.app, state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admission.RespondWithSnapshot(env.ctx, env.c, env.buyer, env.app, challenge, snapshot); err == nil {
			t.Fatal("retained snapshot bypassed owner check")
		}
		for _, bad := range []*protocol.Snapshot{nil, wrongSnapshot} {
			if _, err := admission.RespondWithSnapshot(env.ctx, env.c, env.owner, env.app, challenge, bad); err == nil {
				t.Fatal("snapshot inconsistent with registered commitment accepted")
			}
		}
		response, err := admission.RespondWithSnapshot(env.ctx, env.c, env.owner, env.app, challenge, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := admission.CheckResponse(env.ctx, env.c, env.app, challenge, response); err != nil {
			t.Fatal(err)
		}
		if _, err := env.c.Send(env.ctx, env.ra, nil, "decideAudit", new(big.Int).SetUint64(aid), true); err != nil {
			t.Fatal(err)
		}
		if _, err := admission.RespondWithSnapshot(env.ctx, env.c, env.owner, env.app, challenge, snapshot); err == nil {
			t.Fatal("retained snapshot bypassed terminal audit state")
		}
	}
	assertChallengeCount(t, env, "retained-snapshot", 2)
	aid := newAudit(t, env, "retained-snapshot")
	if _, err := admission.CreateChallenge(env.ctx, env.c, env.ra, aid, env.app, state); err == nil {
		t.Fatal("retaining a snapshot bypassed cumulative challenge budget")
	}
}
