package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// openPostgresIntegrationDB keeps these tests opt-in: local unit-test runs do
// not need a PostgreSQL instance or a configured development database.
func openPostgresIntegrationDB(t *testing.T) *DB {
	t.Helper()
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("ARTEX_PG_DSN is unset; skipping PostgreSQL integration test")
	}
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestPostgresRunEventIdempotency(t *testing.T) {
	d := openPostgresIntegrationDB(t)
	ctx := context.Background()
	runID := fmt.Sprintf("integration-idempotency-%d", time.Now().UnixNano())
	payload := json.RawMessage(`{"attempt":1}`)

	first, err := d.AppendRunEvent(ctx, RunEvent{
		RunID: runID, Kind: EventActionProposed, Source: "integration",
		IdempotencyKey: "action-1", Payload: payload,
	})
	if err != nil {
		t.Fatalf("append first event: %v", err)
	}
	second, err := d.AppendRunEvent(ctx, RunEvent{
		RunID: runID, Kind: EventActionProposed, Source: "retry",
		IdempotencyKey: "action-1", Payload: json.RawMessage(`{"attempt":2}`),
	})
	if err != nil {
		t.Fatalf("append retry event: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("retry event id=%d, want original id %d", second.ID, first.ID)
	}
	if string(second.Payload) != string(payload) {
		t.Fatalf("retry replaced payload: got %s want %s", second.Payload, payload)
	}

	events, err := d.ListRunEvents(ctx, runID, 0, 100)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 || events[0].ID != first.ID {
		t.Fatalf("events=%+v, want one idempotent event", events)
	}
}

func TestPostgresCheckpointRecovery(t *testing.T) {
	d := openPostgresIntegrationDB(t)
	ctx := context.Background()
	runID := fmt.Sprintf("integration-checkpoint-%d", time.Now().UnixNano())

	event, err := d.AppendRunEvent(ctx, RunEvent{
		RunID: runID, Kind: EventCheckpointCreated, Source: "integration",
		IdempotencyKey: "checkpoint-event-1",
		Payload:        json.RawMessage(`{"step":"policy","sequence":7}`),
	})
	if err != nil {
		t.Fatalf("append checkpoint event: %v", err)
	}
	checkpoint, err := d.CreateRunCheckpoint(ctx, RunCheckpoint{
		RunID: runID, ParentEventID: &event.ID, Step: "policy", StateVersion: 3,
		State: json.RawMessage(`{"frontier":[11,12],"cursor":"after-7"}`),
	})
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	latest, err := d.LatestRunCheckpoint(ctx, runID)
	if err != nil {
		t.Fatalf("load latest checkpoint: %v", err)
	}
	if latest == nil || latest.ID != checkpoint.ID || latest.Step != "policy" || latest.StateVersion != 3 {
		t.Fatalf("latest checkpoint=%+v, want id=%d policy v3", latest, checkpoint.ID)
	}
	if latest.ParentEventID == nil || *latest.ParentEventID != event.ID {
		t.Fatalf("checkpoint parent=%v, want event %d", latest.ParentEventID, event.ID)
	}
	var state struct {
		Cursor string `json:"cursor"`
	}
	if err := json.Unmarshal(latest.State, &state); err != nil || state.Cursor != "after-7" {
		t.Fatalf("recovered state=%s err=%v", latest.State, err)
	}
}

func TestPostgresIntentLeaseFencingRace(t *testing.T) {
	d := openPostgresIntegrationDB(t)
	expID, err := d.CreateExploration("lease integration", "exercise lease fencing")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "race"}, 1, nil, "integration")
	if err != nil {
		t.Fatal(err)
	}

	const contenders = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	type result struct {
		lease IntentLease
		ok    bool
		err   error
	}
	results := make(chan result, contenders)
	for i := 0; i < contenders; i++ {
		owner := fmt.Sprintf("integration-worker-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			lease, ok, claimErr := d.Exploration(expID).ClaimIntentLease(intentID, owner, time.Minute)
			results <- result{lease: lease, ok: ok, err: claimErr}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var winner IntentLease
	wins := 0
	for got := range results {
		if got.err != nil {
			t.Fatalf("lease race: %v", got.err)
		}
		if got.ok {
			wins++
			winner = got.lease
		}
	}
	if wins != 1 {
		t.Fatalf("lease race winners=%d, want 1", wins)
	}

	if _, err := store.FencedCompareAndSetIntentState(intentID, "running", "done", winner.Owner, winner.FencingToken); err != nil {
		t.Fatalf("winner fenced transition: %v", err)
	}
	if _, err := store.FencedCompareAndSetIntentState(intentID, "done", "stopped", "stale-worker", winner.FencingToken); !errors.Is(err, ErrIntentLeaseStale) {
		t.Fatalf("stale fenced transition err=%v, want ErrIntentLeaseStale", err)
	}
}

func TestPostgresSchemaIsIdempotent(t *testing.T) {
	d := openPostgresIntegrationDB(t)
	if _, err := d.Exec(schemaSQL); err != nil {
		t.Fatalf("first schema application: %v", err)
	}
	if _, err := d.Exec(schemaSQL); err != nil {
		t.Fatalf("second schema application: %v", err)
	}

	var tables int
	if err := d.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('run_events','run_checkpoints','intent_leases','llm_provider_telemetry')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 4 {
		t.Fatalf("durable control-plane tables=%d, want 4", tables)
	}
}

func TestPostgresProviderTelemetryPersists(t *testing.T) {
	d := openPostgresIntegrationDB(t)
	if err := d.EnsureLLMProviderTelemetryTable(); err != nil {
		t.Fatalf("ensure provider telemetry table: %v", err)
	}
	taskID := fmt.Sprintf("integration-provider-telemetry-%d", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_provider_telemetry WHERE task_id=$1`, taskID) })
	row := &LLMProviderTelemetry{
		TaskID: taskID, Worker: "worker", Role: "planner", Kind: "attempt",
		MemberID: 41, ProfileName: "primary", Model: "fixture-model",
		LatencyMs: 17, InputTokens: 9, OutputTokens: 4, CacheRead: 2,
		FallbackFrom: "primary", FallbackTo: "backup", Status: "ok",
	}
	if err := d.InsertLLMProviderTelemetry(row); err != nil {
		t.Fatalf("insert provider telemetry: %v", err)
	}
	var got LLMProviderTelemetry
	if err := d.QueryRow(`SELECT task_id,worker,role,kind,member_id,profile_name,model,fallback_from,fallback_to,latency_ms,input_tokens,output_tokens,cache_read,cache_write,status
		FROM llm_provider_telemetry WHERE task_id=$1`, taskID).Scan(
		&got.TaskID, &got.Worker, &got.Role, &got.Kind, &got.MemberID, &got.ProfileName, &got.Model,
		&got.FallbackFrom, &got.FallbackTo, &got.LatencyMs, &got.InputTokens, &got.OutputTokens,
		&got.CacheRead, &got.CacheWrite, &got.Status); err != nil {
		t.Fatalf("read persisted telemetry: %v", err)
	}
	if got.ProfileName != row.ProfileName || got.FallbackTo != row.FallbackTo || got.InputTokens != row.InputTokens || got.OutputTokens != row.OutputTokens || got.CacheRead != row.CacheRead {
		t.Fatalf("persisted provider telemetry = %+v, want fields from %+v", got, row)
	}
}
