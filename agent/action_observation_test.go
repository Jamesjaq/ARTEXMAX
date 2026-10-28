package agent

import (
	"encoding/json"
	"testing"
	"time"
)

func validAction() Action {
	return Action{
		ID: "a-1", Tool: "probe", Arguments: json.RawMessage(`{"path":"/"}`),
		TargetScope: "example.test", Capability: "http.read", TimeoutMS: 5000,
		IdempotencyKey: "run-1:a-1", ReadOnly: true, Idempotent: true,
	}
}

func TestActionValidateRequiresExecutionSafetyFields(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Action)
	}{
		{"missing scope", func(a *Action) { a.TargetScope = "" }},
		{"invalid arguments", func(a *Action) { a.Arguments = json.RawMessage("{") }},
		{"missing idempotency", func(a *Action) { a.IdempotencyKey = "" }},
		{"conflicting capability flags", func(a *Action) { a.Destructive = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAction()
			if tc.name == "conflicting capability flags" {
				a.ReadOnly = true
			}
			tc.edit(&a)
			if err := a.Validate(); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestObservationValidateBoundsStoredEvidence(t *testing.T) {
	o := Observation{ActionID: "a-1", Status: "ok", Duration: time.Second, BytesRead: 100, BytesStored: 50}
	if err := o.Validate(); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
	o.BytesStored = 101
	if err := o.Validate(); err == nil {
		t.Fatalf("stored bytes above read bytes should fail")
	}
}

func TestObservationValidateStatus(t *testing.T) {
	o := Observation{ActionID: "a-1", Status: "unknown"}
	if err := o.Validate(); err == nil {
		t.Fatalf("unknown status should fail")
	}
}
