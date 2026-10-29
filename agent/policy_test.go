package agent

import (
	"testing"
	"time"
)

func policyAction() Action {
	return Action{ID: "a1", Tool: "http_request", Arguments: []byte(`{"url":"https://example.test/admin"}`), TargetScope: "example.test", Capability: "http.read", TimeoutMS: 1000, IdempotencyKey: "k1", ReadOnly: true, Idempotent: true}
}

func TestActionDigestChangesWithArguments(t *testing.T) {
	a := policyAction()
	first, err := ActionDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	a.Arguments = []byte(`{"url":"https://example.test/other"}`)
	second, err := ActionDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("argument mutation did not change action digest")
	}
}

func TestEvaluateActionRequiresExactApproval(t *testing.T) {
	a := policyAction()
	now := time.Unix(100, 0)
	p := Policy{Revision: "r1", AllowedTools: map[string]bool{"http_request": true}, AllowedCapabilities: map[string]bool{"http.read": true}, AllowedScopes: []string{"example.test"}, RequireApprovalForDestructive: true}
	a.Destructive, a.ReadOnly = true, false
	d := EvaluateAction(a, p, PolicyUsage{}, nil, now)
	if !d.NeedsApproval || d.Allowed {
		t.Fatalf("got %+v", d)
	}
	digest, _ := ActionDigest(a)
	approval := &Approval{ActionDigest: digest, PolicyRevision: "r1", Reviewer: "operator", ExpiresAt: now.Add(time.Minute), Allowed: true}
	d = EvaluateAction(a, p, PolicyUsage{}, approval, now)
	if !d.Allowed {
		t.Fatalf("valid approval denied: %+v", d)
	}
	approval.ActionDigest = "stale"
	d = EvaluateAction(a, p, PolicyUsage{}, approval, now)
	if d.Allowed {
		t.Fatal("stale approval was accepted")
	}
}

func TestEvaluateActionScopeAndBudget(t *testing.T) {
	a := policyAction()
	p := Policy{Revision: "r1", AllowedTools: map[string]bool{"http_request": true}, AllowedCapabilities: map[string]bool{"http.read": true}, AllowedScopes: []string{"*.example.test"}, MaxActions: 1}
	if d := EvaluateAction(a, p, PolicyUsage{Actions: 1}, nil, time.Now()); d.Allowed {
		t.Fatal("exhausted budget was allowed")
	}
	a.TargetScope = "other.test"
	if d := EvaluateAction(a, p, PolicyUsage{}, nil, time.Now()); d.Allowed {
		t.Fatal("out-of-scope action was allowed")
	}
}
