package db

import (
	"encoding/json"
	"sort"
)

// RunProjection is the bounded state reconstructed from immutable run events.
// It is intentionally independent of PostgreSQL so restart/replay tests can
// compare projections from the same event stream.
type RunProjection struct {
	RunID              string
	Status             string
	LastEventID        int64
	LastCheckpointStep string
	Actions            int
	AllowedActions     int
	DeniedActions      int
	Observations       int
	FindingsUpdated    int
}

// ProjectRunEvents deterministically folds events in ID order. Duplicate event
// IDs and duplicate idempotency keys are ignored, matching the database ledger
// contract during replay or at-least-once delivery.
func ProjectRunEvents(events []RunEvent) RunProjection {
	ordered := append([]RunEvent(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	seenIDs := map[int64]struct{}{}
	seenKeys := map[string]struct{}{}
	var p RunProjection
	for _, event := range ordered {
		if event.ID != 0 {
			if _, ok := seenIDs[event.ID]; ok {
				continue
			}
			seenIDs[event.ID] = struct{}{}
		}
		if event.IdempotencyKey != "" {
			if _, ok := seenKeys[event.IdempotencyKey]; ok {
				continue
			}
			seenKeys[event.IdempotencyKey] = struct{}{}
		}
		if p.RunID == "" {
			p.RunID = event.RunID
		}
		if event.ID > p.LastEventID {
			p.LastEventID = event.ID
		}
		var payload struct {
			Status  string `json:"status"`
			Allowed bool   `json:"allowed"`
		}
		_ = json.Unmarshal(event.Payload, &payload)
		switch event.Kind {
		case EventRunStatusChanged:
			if payload.Status != "" {
				p.Status = payload.Status
			}
		case EventActionProposed:
			p.Actions++
		case EventPolicyEvaluated:
			if payload.Allowed {
				p.AllowedActions++
			} else {
				p.DeniedActions++
			}
		case EventObservationRecorded:
			p.Observations++
		case EventFindingUpdated:
			p.FindingsUpdated++
		case EventCheckpointCreated:
			var checkpoint struct {
				Step string `json:"step"`
			}
			if json.Unmarshal(event.Payload, &checkpoint) == nil {
				p.LastCheckpointStep = checkpoint.Step
			}
		}
	}
	return p
}
