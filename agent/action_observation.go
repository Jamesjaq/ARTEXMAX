package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Action is the model-facing request before policy evaluation. An executor must
// never run an Action until the surrounding policy gate has accepted it.
type Action struct {
	ID             string          `json:"id"`
	Tool           string          `json:"tool"`
	Arguments      json.RawMessage `json:"arguments"`
	TargetScope    string          `json:"target_scope"`
	Capability     string          `json:"capability"`
	TimeoutMS      int             `json:"timeout_ms"`
	IdempotencyKey string          `json:"idempotency_key"`
	ReadOnly       bool            `json:"read_only"`
	Destructive    bool            `json:"destructive"`
	Idempotent     bool            `json:"idempotent"`
}

func (a Action) Validate() error {
	if strings.TrimSpace(a.ID) == "" {
		return errors.New("action id is required")
	}
	if strings.TrimSpace(a.Tool) == "" {
		return errors.New("action tool is required")
	}
	if strings.TrimSpace(a.TargetScope) == "" {
		return errors.New("action target scope is required")
	}
	if len(a.Arguments) == 0 || !json.Valid(a.Arguments) {
		return errors.New("action arguments must be valid JSON")
	}
	if a.TimeoutMS <= 0 || a.TimeoutMS > 24*60*60*1000 {
		return errors.New("action timeout must be between 1ms and 24h")
	}
	if strings.TrimSpace(a.IdempotencyKey) == "" {
		return errors.New("action idempotency key is required")
	}
	if a.Destructive && a.ReadOnly {
		return errors.New("action cannot be both destructive and read-only")
	}
	return nil
}

// Observation is the compact executor result. Raw output is represented by
// ArtifactRefs so the model-facing context can stay bounded.
type Observation struct {
	ActionID       string        `json:"action_id"`
	Status         string        `json:"status"`
	Summary        string        `json:"summary"`
	ErrorCode      string        `json:"error_code,omitempty"`
	ExitCode       *int          `json:"exit_code,omitempty"`
	Duration       time.Duration `json:"duration_ns"`
	BytesRead      int64         `json:"bytes_read"`
	BytesStored    int64         `json:"bytes_stored"`
	Truncated      bool          `json:"truncated"`
	Redacted       bool          `json:"redacted"`
	ArtifactRefs   []string      `json:"artifact_refs,omitempty"`
	ProvenanceNote string        `json:"provenance_note,omitempty"`
}

func (o Observation) Validate() error {
	if strings.TrimSpace(o.ActionID) == "" {
		return errors.New("observation action id is required")
	}
	switch o.Status {
	case "ok", "error", "denied", "cancelled", "timeout", "skipped":
	default:
		return fmt.Errorf("invalid observation status %q", o.Status)
	}
	if o.Duration < 0 || o.BytesRead < 0 || o.BytesStored < 0 {
		return errors.New("observation metrics cannot be negative")
	}
	if o.BytesStored > o.BytesRead {
		return errors.New("stored bytes cannot exceed read bytes")
	}
	return nil
}
