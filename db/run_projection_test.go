package db

import (
	"encoding/json"
	"testing"
)

func TestProjectRunEventsIsIdempotent(t *testing.T) {
	payload := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	events := []RunEvent{
		{ID: 3, RunID: "r1", Kind: EventObservationRecorded, IdempotencyKey: "obs-1", Payload: payload(map[string]any{})},
		{ID: 1, RunID: "r1", Kind: EventActionProposed, IdempotencyKey: "act-1", Payload: payload(map[string]any{})},
		{ID: 2, RunID: "r1", Kind: EventPolicyEvaluated, IdempotencyKey: "pol-1", Payload: payload(map[string]any{"allowed": false})},
		{ID: 4, RunID: "r1", Kind: EventCheckpointCreated, IdempotencyKey: "cp-1", Payload: payload(map[string]any{"step": "policy"})},
		{ID: 5, RunID: "r1", Kind: EventRunStatusChanged, IdempotencyKey: "status-1", Payload: payload(map[string]any{"status": "paused"})},
	}
	got := ProjectRunEvents(append(events, events[0], RunEvent{ID: 99, RunID: "r1", Kind: EventActionProposed, IdempotencyKey: "act-1", Payload: payload(map[string]any{})}))
	want := RunProjection{RunID: "r1", Status: "paused", LastEventID: 5, LastCheckpointStep: "policy", Actions: 1, DeniedActions: 1, Observations: 1}
	if got != want {
		t.Fatalf("projection=%+v want=%+v", got, want)
	}
}
