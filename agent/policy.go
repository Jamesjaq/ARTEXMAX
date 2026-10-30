package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// Policy is the execution-time authorization contract. An LLM proposal is not
// executable until EvaluateAction returns allow or an exact approval matches.
type Policy struct {
	Revision                      string
	RunID                         string
	Checkpoint                    string
	AllowedTools                  map[string]bool
	AllowedCapabilities           map[string]bool
	AllowedScopes                 []string
	RequireApprovalForDestructive bool
	MaxActions                    int
	MaxBytes                      int64
	Deadline                      time.Time
}

type PolicyUsage struct {
	Actions int
	Bytes   int64
}

type Approval struct {
	RunID          string
	Checkpoint     string
	PolicyRevision string
	ActionDigest   string
	Reviewer       string
	ExpiresAt      time.Time
	Allowed        bool
}

type PolicyDecision struct {
	ActionDigest  string
	Allowed       bool
	NeedsApproval bool
	Reason        string
}

// ActionDigest canonicalizes the action fields that affect execution. Approval
// records must store this digest and may never be reused after arguments change.
func ActionDigest(a Action) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	var args any
	if err := json.Unmarshal(a.Arguments, &args); err != nil {
		return "", err
	}
	canonical := struct {
		ID, Tool, TargetScope, Capability string
		IdempotencyKey                    string
		Arguments                         any
		TimeoutMS                         int
		ReadOnly, Destructive, Idempotent bool
	}{a.ID, a.Tool, a.TargetScope, a.Capability, a.IdempotencyKey, args, a.TimeoutMS, a.ReadOnly, a.Destructive, a.Idempotent}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func EvaluateAction(a Action, p Policy, usage PolicyUsage, approval *Approval, now time.Time) PolicyDecision {
	digest, err := ActionDigest(a)
	if err != nil {
		return PolicyDecision{Allowed: false, Reason: err.Error()}
	}
	deny := func(reason string) PolicyDecision { return PolicyDecision{ActionDigest: digest, Reason: reason} }
	if len(p.AllowedTools) == 0 || !p.AllowedTools[a.Tool] {
		return deny("tool is not allowed by policy")
	}
	if len(p.AllowedCapabilities) == 0 || !p.AllowedCapabilities[a.Capability] {
		return deny("capability is not allowed by policy")
	}
	if len(p.AllowedScopes) == 0 {
		return deny("no authorized target scope is configured")
	}
	inScope := false
	for _, pattern := range p.AllowedScopes {
		if ok, _ := path.Match(pattern, a.TargetScope); ok {
			inScope = true
			break
		}
	}
	if !inScope {
		return deny("target is outside the authorized scope")
	}
	if p.MaxActions > 0 && usage.Actions >= p.MaxActions {
		return deny("action budget exhausted")
	}
	if p.MaxBytes > 0 && usage.Bytes >= p.MaxBytes {
		return deny("byte budget exhausted")
	}
	if !p.Deadline.IsZero() && !now.Before(p.Deadline) {
		return deny("policy deadline expired")
	}
	if a.Destructive && p.RequireApprovalForDestructive {
		if strings.TrimSpace(p.RunID) == "" || strings.TrimSpace(p.Checkpoint) == "" {
			return deny("approval run and checkpoint context is unavailable")
		}
		if approval == nil {
			return PolicyDecision{ActionDigest: digest, NeedsApproval: true, Reason: "exact human approval required"}
		}
		if !approval.Allowed || approval.ActionDigest != digest || approval.PolicyRevision != p.Revision ||
			approval.RunID != p.RunID || approval.Checkpoint != p.Checkpoint ||
			approval.ExpiresAt.IsZero() || !now.Before(approval.ExpiresAt) || strings.TrimSpace(approval.Reviewer) == "" {
			return deny("approval does not match the exact action and policy revision")
		}
	}
	return PolicyDecision{ActionDigest: digest, Allowed: true, Reason: "allowed by policy"}
}

func (p Policy) Validate() error {
	if strings.TrimSpace(p.Revision) == "" {
		return errors.New("policy revision is required")
	}
	if len(p.AllowedTools) == 0 || len(p.AllowedCapabilities) == 0 {
		return errors.New("policy must explicitly configure tool and capability allowlists")
	}
	if p.MaxActions < 0 || p.MaxBytes < 0 {
		return errors.New("policy budgets cannot be negative")
	}
	for _, scope := range p.AllowedScopes {
		if strings.TrimSpace(scope) == "" {
			return fmt.Errorf("empty authorized scope")
		}
	}
	return nil
}
