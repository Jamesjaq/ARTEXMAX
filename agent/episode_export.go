package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Autumn-27/artex/db"
)

const (
	EpisodePackageVersion = 1
	maxEpisodeEvents      = 256
	maxEpisodeEvidence    = 128
	maxEvidenceBytes      = 64 << 10
	maxPackageBytes       = 1 << 20
)

// EpisodeProvenance identifies the deterministic inputs used to produce a package.
// It contains references and digests only; raw prompts, bodies, and secrets do not
// belong in an episode package.
type EpisodeProvenance struct {
	Harness   string `json:"harness"`
	ProfileID string `json:"profile_id"`
	Profile   string `json:"profile_digest,omitempty"`
	Policy    string `json:"policy_digest,omitempty"`
	Fixture   string `json:"fixture_digest,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// EpisodeEvidence is a bounded evidence item. Data is optional and is intended for
// small deterministic fixtures; larger evidence should be represented by Digest.
type EpisodeEvidence struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Digest string `json:"sha256"`
	Size   int    `json:"size"`
	Data   []byte `json:"data,omitempty"`
	Source string `json:"source,omitempty"`
}

// EpisodeMetrics are derived from the event stream and therefore can be checked
// after import without trusting caller-provided counters.
type EpisodeMetrics struct {
	Events        int `json:"events"`
	Actions       int `json:"actions"`
	Allowed       int `json:"allowed"`
	Denied        int `json:"denied"`
	Observations  int `json:"observations"`
	EvidenceItems int `json:"evidence_items"`
}

// EpisodePackage is a self-contained, bounded replay unit. Hash is SHA-256 over
// the canonical JSON representation with Hash cleared.
type EpisodePackage struct {
	Version    int                `json:"version"`
	RunID      string             `json:"run_id"`
	Provenance EpisodeProvenance  `json:"provenance"`
	Events     []db.RunEvent      `json:"events"`
	Evidence   []EpisodeEvidence  `json:"evidence,omitempty"`
	Metrics    EpisodeMetrics     `json:"metrics"`
	Checkpoint *EpisodeCheckpoint `json:"checkpoint,omitempty"`
	Hash       string             `json:"sha256"`
}

// EpisodeCheckpoint is the in-memory restart point reconstructed from the event
// stream, not a second source of truth.
type EpisodeCheckpoint struct {
	EventID int64  `json:"event_id"`
	Step    string `json:"step"`
}

// EpisodeRestart is the state recovered by replaying an imported package.
type EpisodeRestart struct {
	Projection db.RunProjection
	Checkpoint *EpisodeCheckpoint
	Resumed    bool
}

// ExportEpisodePackage converts a deterministic episode result into bounded run
// events and returns canonical JSON with an integrity hash.
func ExportEpisodePackage(runID string, result EpisodeResult, provenance EpisodeProvenance, evidence []EpisodeEvidence) ([]byte, error) {
	if runID == "" {
		return nil, errors.New("run id is required")
	}
	if len(result.Events) > maxEpisodeEvents || len(evidence) > maxEpisodeEvidence {
		return nil, errors.New("episode package exceeds item bound")
	}
	pkg := EpisodePackage{Version: EpisodePackageVersion, RunID: runID, Provenance: provenance}
	for i, event := range result.Events {
		payload, err := json.Marshal(struct {
			ActionID     string `json:"action_id,omitempty"`
			ActionDigest string `json:"action_digest,omitempty"`
			Status       string `json:"status,omitempty"`
			Reason       string `json:"reason,omitempty"`
			Allowed      bool   `json:"allowed,omitempty"`
		}{
			ActionID: event.ActionID, ActionDigest: event.ActionDigest, Status: event.Status,
			Reason: event.Reason, Allowed: event.Status == "allowed",
		})
		if err != nil {
			return nil, err
		}
		kind := event.Kind
		if kind == "" {
			return nil, fmt.Errorf("event %d has no kind", i)
		}
		if kind == db.EventCheckpointCreated && event.Reason != "" {
			payload, err = json.Marshal(struct {
				Step string `json:"step"`
			}{Step: event.Reason})
			if err != nil {
				return nil, err
			}
		}
		pkg.Events = append(pkg.Events, db.RunEvent{ID: int64(i + 1), RunID: runID, Kind: kind, SchemaVersion: 1, Source: "episode", IdempotencyKey: fmt.Sprintf("episode-%d", i+1), Payload: payload})
		if kind == "checkpoint_created" {
			var cp struct {
				Step string `json:"step"`
			}
			if json.Unmarshal(payload, &cp) == nil && cp.Step != "" {
				pkg.Checkpoint = &EpisodeCheckpoint{EventID: int64(i + 1), Step: cp.Step}
			}
		}
	}
	for i := range evidence {
		item := evidence[i]
		if item.ID == "" {
			return nil, fmt.Errorf("evidence %d has no id", i)
		}
		if len(item.Data) > maxEvidenceBytes {
			return nil, fmt.Errorf("evidence %q exceeds size bound", item.ID)
		}
		if item.Size == 0 {
			item.Size = len(item.Data)
		}
		if item.Size < 0 || item.Size > maxEvidenceBytes {
			return nil, fmt.Errorf("evidence %q has invalid size", item.ID)
		}
		if item.Size != len(item.Data) {
			return nil, fmt.Errorf("evidence %q must include its bytes; external artifact resolution is not supported", item.ID)
		}
		if item.Digest == "" {
			sum := sha256.Sum256(item.Data)
			item.Digest = hex.EncodeToString(sum[:])
		}
		if item.Size == len(item.Data) {
			sum := sha256.Sum256(item.Data)
			if item.Digest != hex.EncodeToString(sum[:]) {
				return nil, fmt.Errorf("evidence %q digest mismatch", item.ID)
			}
		}
		pkg.Evidence = append(pkg.Evidence, item)
	}
	pkg.Metrics = metricsFor(pkg.Events, len(pkg.Evidence))
	return marshalEpisodePackage(pkg)
}

// ExportPackage is a convenience method for callers holding an EpisodeResult.
func (r EpisodeResult) ExportPackage(runID string, provenance EpisodeProvenance, evidence []EpisodeEvidence) ([]byte, error) {
	return ExportEpisodePackage(runID, r, provenance, evidence)
}

// ImportEpisodePackage verifies bounds, evidence digests, and the package hash.
func ImportEpisodePackage(data []byte) (EpisodePackage, error) {
	if len(data) == 0 || len(data) > maxPackageBytes {
		return EpisodePackage{}, errors.New("episode package size is out of bounds")
	}
	var pkg EpisodePackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return EpisodePackage{}, fmt.Errorf("decode episode package: %w", err)
	}
	if pkg.Version != EpisodePackageVersion || pkg.RunID == "" || len(pkg.Events) > maxEpisodeEvents || len(pkg.Evidence) > maxEpisodeEvidence {
		return EpisodePackage{}, errors.New("invalid episode package bounds or version")
	}
	if pkg.Hash == "" {
		return EpisodePackage{}, errors.New("episode package hash is required")
	}
	for _, item := range pkg.Evidence {
		if item.ID == "" || len(item.Data) > maxEvidenceBytes || item.Size < 0 || item.Size > maxEvidenceBytes {
			return EpisodePackage{}, fmt.Errorf("evidence %q exceeds size bound", item.ID)
		}
		if item.Size != len(item.Data) {
			return EpisodePackage{}, fmt.Errorf("evidence %q bytes are absent; external artifact resolution is not supported", item.ID)
		}
		sum := sha256.Sum256(item.Data)
		if item.Digest != hex.EncodeToString(sum[:]) {
			return EpisodePackage{}, fmt.Errorf("evidence %q digest mismatch", item.ID)
		}
	}
	want := pkg.Hash
	pkg.Hash = ""
	canonical, err := json.Marshal(pkg)
	if err != nil {
		return EpisodePackage{}, err
	}
	sum := sha256.Sum256(canonical)
	if want != hex.EncodeToString(sum[:]) {
		return EpisodePackage{}, errors.New("episode package hash mismatch")
	}
	pkg.Hash = want
	var derivedCheckpoint *EpisodeCheckpoint
	lastID := int64(0)
	for _, event := range pkg.Events {
		if event.RunID != pkg.RunID || event.ID <= lastID || event.ID <= 0 || event.Kind == "" || !json.Valid(event.Payload) {
			return EpisodePackage{}, errors.New("episode event stream is invalid or belongs to another run")
		}
		lastID = event.ID
		if event.Kind == db.EventCheckpointCreated {
			var payload struct {
				Step string `json:"step"`
			}
			if err := json.Unmarshal(event.Payload, &payload); err != nil || payload.Step == "" {
				return EpisodePackage{}, errors.New("episode checkpoint event is invalid")
			}
			derivedCheckpoint = &EpisodeCheckpoint{EventID: event.ID, Step: payload.Step}
		}
	}
	if !sameEpisodeCheckpoint(pkg.Checkpoint, derivedCheckpoint) {
		return EpisodePackage{}, errors.New("episode checkpoint does not match the event stream")
	}
	if got := metricsFor(pkg.Events, len(pkg.Evidence)); got != pkg.Metrics {
		return EpisodePackage{}, errors.New("episode package metrics mismatch")
	}
	return pkg, nil
}

// VerifyEpisodePackage checks integrity without exposing a separate trust path.
func VerifyEpisodePackage(data []byte) error {
	_, err := ImportEpisodePackage(data)
	return err
}

// RestartEpisodePackage simulates a process restart by projecting only the
// imported immutable event stream and recovering its latest checkpoint.
func RestartEpisodePackage(pkg EpisodePackage) (EpisodeRestart, error) {
	// Preserve the caller-supplied hash: re-marshalling through the export helper
	// would silently calculate a new digest and bless any in-memory mutation.
	data, err := json.Marshal(pkg)
	if err != nil {
		return EpisodeRestart{}, err
	}
	verified, err := ImportEpisodePackage(data)
	if err != nil {
		return EpisodeRestart{}, err
	}
	projection := db.ProjectRunEvents(verified.Events)
	var checkpoint *EpisodeCheckpoint
	if verified.Checkpoint != nil {
		cp := *verified.Checkpoint
		checkpoint = &cp
	}
	return EpisodeRestart{Projection: projection, Checkpoint: checkpoint, Resumed: checkpoint != nil}, nil
}

func sameEpisodeCheckpoint(a, b *EpisodeCheckpoint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.EventID == b.EventID && a.Step == b.Step
}

func marshalEpisodePackage(pkg EpisodePackage) ([]byte, error) {
	pkg.Hash = ""
	canonical, err := json.Marshal(pkg)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	pkg.Hash = hex.EncodeToString(sum[:])
	out, err := json.Marshal(pkg)
	if err != nil {
		return nil, err
	}
	if len(out) > maxPackageBytes {
		return nil, errors.New("episode package exceeds byte bound")
	}
	return out, nil
}

func metricsFor(events []db.RunEvent, evidence int) EpisodeMetrics {
	m := EpisodeMetrics{Events: len(events), EvidenceItems: evidence}
	for _, event := range events {
		switch event.Kind {
		case db.EventActionProposed:
			m.Actions++
		case db.EventPolicyEvaluated:
			var payload struct {
				Allowed bool `json:"allowed"`
			}
			_ = json.Unmarshal(event.Payload, &payload)
			if payload.Allowed {
				m.Allowed++
			} else {
				m.Denied++
			}
		case db.EventObservationRecorded:
			m.Observations++
		}
	}
	return m
}
