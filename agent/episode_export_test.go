package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestEpisodePackageExportImportVerifiesHash(t *testing.T) {
	result := EpisodeResult{Events: []EpisodeEvent{
		{Kind: db.EventActionProposed, ActionID: "a1"},
		{Kind: db.EventPolicyEvaluated, ActionID: "a1", ActionDigest: "digest-a1", Status: "allowed"},
		{Kind: db.EventObservationRecorded, ActionID: "a1", Status: "ok"},
		{Kind: db.EventRunStatusChanged, Status: "completed"},
	}}
	provenance := EpisodeProvenance{Harness: "fixture-v1", ProfileID: "profile-1", Profile: "profile-hash", Policy: "policy-hash", Fixture: "fixture-hash"}
	evidence := []EpisodeEvidence{{ID: "obs-a1", Kind: "observation", Data: []byte("bounded output"), Source: "fixture"}}
	first, err := ExportEpisodePackage("run-1", result, provenance, evidence)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExportEpisodePackage("run-1", result, provenance, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("repeated export was not deterministic")
	}
	pkg, err := ImportEpisodePackage(first)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Hash == "" || pkg.Metrics.Events != 4 || pkg.Metrics.EvidenceItems != 1 {
		t.Fatalf("unexpected package: %+v", pkg)
	}
	var tampered map[string]any
	if err := json.Unmarshal(first, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["run_id"] = "run-tampered"
	bad, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEpisodePackage(bad); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered package verification error=%v", err)
	}
}

func TestRestartEpisodePackageRecoversProjectionAndCheckpoint(t *testing.T) {
	result := EpisodeResult{Events: []EpisodeEvent{
		{Kind: db.EventActionProposed, ActionID: "a1"},
		{Kind: db.EventPolicyEvaluated, ActionID: "a1", Status: "allowed"},
		{Kind: db.EventCheckpointCreated, Status: "policy"},
		{Kind: db.EventObservationRecorded, ActionID: "a1", Status: "ok"},
		{Kind: db.EventRunStatusChanged, Status: "paused"},
	}}
	result.Events[2].Reason = "policy"
	data, err := ExportEpisodePackage("run-restart", result, EpisodeProvenance{Harness: "fixture-v1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := ImportEpisodePackage(data)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := RestartEpisodePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	want := db.RunProjection{RunID: "run-restart", Status: "paused", LastEventID: 5, LastCheckpointStep: "policy", Actions: 1, AllowedActions: 1, Observations: 1}
	if restarted.Projection != want {
		t.Fatalf("projection=%+v want=%+v", restarted.Projection, want)
	}
	if !restarted.Resumed || restarted.Checkpoint == nil || restarted.Checkpoint.Step != "policy" {
		t.Fatalf("restart=%+v", restarted)
	}
	pkg.Events[0].Kind = db.EventFindingUpdated
	if _, err := RestartEpisodePackage(pkg); err == nil {
		t.Fatal("restart accepted a mutated in-memory package with a stale hash")
	}
	// Re-import the original bytes and mutate only the checkpoint projection.
	pkg, err = ImportEpisodePackage(data)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Checkpoint.Step = "different"
	if _, err := RestartEpisodePackage(pkg); err == nil {
		t.Fatal("restart accepted a checkpoint inconsistent with its package hash")
	}
}

func TestEpisodeExportRejectsMissingExternalEvidenceBytes(t *testing.T) {
	_, err := ExportEpisodePackage("run-evidence", EpisodeResult{Events: []EpisodeEvent{{Kind: db.EventRunStatusChanged, Status: "completed"}}}, EpisodeProvenance{Harness: "fixture-v1"}, []EpisodeEvidence{{ID: "artifact-1", Kind: "body", Digest: strings.Repeat("a", 64), Size: 123}})
	if err == nil || !strings.Contains(err.Error(), "must include its bytes") {
		t.Fatalf("missing evidence bytes accepted: %v", err)
	}
}
