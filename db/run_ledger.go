package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RunEvent is an immutable control-plane event. Large outputs belong in the
// evidence store; Payload should contain bounded metadata and artifact refs.
type RunEvent struct {
	ID             int64           `json:"id"`
	RunID          string          `json:"run_id"`
	ParentID       *int64          `json:"parent_id,omitempty"`
	Kind           string          `json:"kind"`
	SchemaVersion  int             `json:"schema_version"`
	Source         string          `json:"source"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	Payload        json.RawMessage `json:"payload"`
	CreatedAt      time.Time       `json:"created_at"`
}

const (
	EventActionProposed      = "action_proposed"
	EventPolicyEvaluated     = "policy_evaluated"
	EventApprovalRequested   = "approval_requested"
	EventActionExecuted      = "action_executed"
	EventObservationRecorded = "observation_recorded"
	EventFindingUpdated      = "finding_updated"
	EventCheckpointCreated   = "checkpoint_created"
	EventCondensationCreated = "condensation_created"
	EventRunStatusChanged    = "run_status_changed"
)

// AppendRunEvent writes one event exactly once when idempotencyKey is set.
// Empty idempotency keys are allowed for informational events. The caller owns
// payload size/redaction policy; this layer deliberately stores only JSON.
func (d *DB) AppendRunEvent(ctx context.Context, in RunEvent) (*RunEvent, error) {
	if d == nil || d.DB == nil {
		return nil, errors.New("nil database")
	}
	if in.RunID == "" {
		return nil, errors.New("run_id is required")
	}
	if in.Kind == "" {
		return nil, errors.New("event kind is required")
	}
	if in.SchemaVersion <= 0 {
		in.SchemaVersion = 1
	}
	if len(in.Payload) == 0 {
		in.Payload = json.RawMessage(`{}`)
	}
	if !json.Valid(in.Payload) {
		return nil, errors.New("event payload must be valid JSON")
	}
	var out RunEvent
	var parent sql.NullInt64
	var key sql.NullString
	err := d.QueryRowContext(ctx, `
INSERT INTO run_events(run_id, parent_id, kind, schema_version, source, idempotency_key, payload)
VALUES ($1, $2, $3, $4, NULLIF($5,''), NULLIF($6,''), $7::jsonb)
ON CONFLICT (run_id, idempotency_key) WHERE idempotency_key IS NOT NULL
DO UPDATE SET id = run_events.id
RETURNING id, run_id, parent_id, kind, schema_version, source, idempotency_key, payload, created_at`,
		in.RunID, in.ParentID, in.Kind, in.SchemaVersion, in.Source, in.IdempotencyKey, string(in.Payload)).Scan(
		&out.ID, &out.RunID, &parent, &out.Kind, &out.SchemaVersion, &out.Source, &key, &out.Payload, &out.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("append run event: %w", err)
	}
	if parent.Valid {
		out.ParentID = &parent.Int64
	}
	if key.Valid {
		out.IdempotencyKey = key.String
	}
	return &out, nil
}

// ListRunEvents returns a bounded ordered slice. limit <= 0 means the default
// safety bound, never an unbounded transcript query.
func (d *DB) ListRunEvents(ctx context.Context, runID string, afterID int64, limit int) ([]RunEvent, error) {
	if runID == "" {
		return nil, errors.New("run_id is required")
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := d.QueryContext(ctx, `
SELECT id, run_id, parent_id, kind, schema_version, source, idempotency_key, payload, created_at
FROM run_events
WHERE run_id=$1 AND id>$2
ORDER BY id ASC
LIMIT $3`, runID, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list run events: %w", err)
	}
	defer rows.Close()
	var out []RunEvent
	for rows.Next() {
		var e RunEvent
		var parent sql.NullInt64
		var key sql.NullString
		if err := rows.Scan(&e.ID, &e.RunID, &parent, &e.Kind, &e.SchemaVersion, &e.Source, &key, &e.Payload, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan run event: %w", err)
		}
		if parent.Valid {
			e.ParentID = &parent.Int64
		}
		if key.Valid {
			e.IdempotencyKey = key.String
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate run events: %w", err)
	}
	return out, nil
}

// RunCheckpoint is a bounded resumable projection. Raw evidence and full
// transcripts are referenced by IDs, never embedded in State.
type RunCheckpoint struct {
	ID            int64           `json:"id"`
	RunID         string          `json:"run_id"`
	ParentEventID *int64          `json:"parent_event_id,omitempty"`
	Step          string          `json:"step"`
	StateVersion  int             `json:"state_version"`
	State         json.RawMessage `json:"state"`
	CreatedAt     time.Time       `json:"created_at"`
}

func (d *DB) CreateRunCheckpoint(ctx context.Context, in RunCheckpoint) (*RunCheckpoint, error) {
	if d == nil || d.DB == nil {
		return nil, errors.New("nil database")
	}
	if in.RunID == "" || in.Step == "" {
		return nil, errors.New("run_id and step are required")
	}
	if in.StateVersion <= 0 {
		in.StateVersion = 1
	}
	if len(in.State) == 0 {
		in.State = json.RawMessage(`{}`)
	}
	if !json.Valid(in.State) {
		return nil, errors.New("checkpoint state must be valid JSON")
	}
	var out RunCheckpoint
	var parent sql.NullInt64
	err := d.QueryRowContext(ctx, `
INSERT INTO run_checkpoints(run_id, parent_event_id, step, state_version, state)
VALUES ($1, $2, $3, $4, $5::jsonb)
RETURNING id, run_id, parent_event_id, step, state_version, state, created_at`,
		in.RunID, in.ParentEventID, in.Step, in.StateVersion, string(in.State)).Scan(
		&out.ID, &out.RunID, &parent, &out.Step, &out.StateVersion, &out.State, &out.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create run checkpoint: %w", err)
	}
	if parent.Valid {
		out.ParentEventID = &parent.Int64
	}
	return &out, nil
}

func (d *DB) LatestRunCheckpoint(ctx context.Context, runID string) (*RunCheckpoint, error) {
	if runID == "" {
		return nil, errors.New("run_id is required")
	}
	var out RunCheckpoint
	var parent sql.NullInt64
	err := d.QueryRowContext(ctx, `
SELECT id, run_id, parent_event_id, step, state_version, state, created_at
FROM run_checkpoints WHERE run_id=$1 ORDER BY id DESC LIMIT 1`, runID).Scan(
		&out.ID, &out.RunID, &parent, &out.Step, &out.StateVersion, &out.State, &out.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest run checkpoint: %w", err)
	}
	if parent.Valid {
		out.ParentEventID = &parent.Int64
	}
	return &out, nil
}
