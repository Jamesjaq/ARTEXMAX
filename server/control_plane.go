package server

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
)

// taskRunEvent is deliberately small. The run ledger stores control-plane
// metadata only; prompts, completions, and tool output remain in their existing
// transcript/evidence stores.
type taskRunEvent struct {
	TaskID string `json:"task_id"`
	Agent  string `json:"agent"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
	Tokens int    `json:"tokens,omitempty"`
	At     string `json:"at"`
}

func (s *Server) appendTaskRunEvent(taskID, agentKey, kind, status string, tokens int, callErr error) *db.RunEvent {
	if s == nil || s.m == nil || s.m.pg == nil || taskID == "" {
		return nil
	}
	payload := taskRunEvent{TaskID: taskID, Agent: agentKey, Status: status, Tokens: tokens, At: time.Now().UTC().Format(time.RFC3339Nano)}
	if callErr != nil {
		payload.Error = callErr.Error()
		if len(payload.Error) > 512 {
			payload.Error = payload.Error[:512]
		}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	e, err := s.m.pg.AppendRunEvent(context.Background(), db.RunEvent{
		RunID: taskID, Kind: kind, SchemaVersion: 1, Source: "server.task_llm", Payload: b,
	})
	if err != nil {
		// Ledger persistence must not make an otherwise valid provider call fail;
		// the failure is visible to operators and the normal transcript remains.
		log.Printf("[control-plane] task %s: append %s: %v", taskID, kind, err)
		return nil
	}
	return e
}

func (s *Server) checkpointTaskRun(taskID, agentKey, step, status string, parent *db.RunEvent) {
	if s == nil || s.m == nil || s.m.pg == nil || taskID == "" {
		return
	}
	state, err := json.Marshal(taskRunEvent{TaskID: taskID, Agent: agentKey, Status: status, At: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return
	}
	var parentID *int64
	if parent != nil {
		parentID = &parent.ID
	}
	if _, err := s.m.pg.CreateRunCheckpoint(context.Background(), db.RunCheckpoint{
		RunID: taskID, ParentEventID: parentID, Step: step, StateVersion: 1, State: state,
	}); err != nil {
		log.Printf("[control-plane] task %s: checkpoint %s: %v", taskID, step, err)
	}
}
