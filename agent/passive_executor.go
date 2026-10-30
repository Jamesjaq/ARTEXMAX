package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PassiveRunner executes only validated passive profiles. It keeps request
// deduplication local to one run so repeated checks cannot amplify traffic.
type PassiveRunner struct {
	Client httpDoer
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// AuthorizedPassiveRun is the result of a policy-gated passive run. Decisions
// are returned for every profile check, including checks denied before any
// network request is made, so the caller can persist an auditable ledger event.
type AuthorizedPassiveRun struct {
	Observations []Observation
	Decisions    []PolicyDecision
	Usage        PolicyUsage
}

func NewPassiveRunner(client httpDoer) *PassiveRunner {
	if client == nil {
		client = &http.Client{}
	}
	return &PassiveRunner{Client: client}
}

func (r *PassiveRunner) Run(ctx context.Context, profile PassiveProfile, secret []byte, authContext string) ([]Observation, error) {
	if err := profile.Verify(secret); err != nil {
		return nil, err
	}
	return r.runVerified(ctx, profile, authContext, nil, make(map[string]struct{})), nil
}

// RunAuthorized is the control-plane entry point for passive execution. Each
// check is converted into the same typed Action contract used by other
// executors and must pass EvaluateAction before the HTTP client is touched.
// The legacy Run method remains available for callers that already perform
// authorization outside this package; new orchestration code should use this
// method so policy and observation events stay coupled.
func (r *PassiveRunner) RunAuthorized(ctx context.Context, profile PassiveProfile, secret []byte, authContext string, policy Policy, usage PolicyUsage, approval *Approval, now time.Time) (AuthorizedPassiveRun, error) {
	if err := profile.Verify(secret); err != nil {
		return AuthorizedPassiveRun{}, err
	}
	if err := policy.Validate(); err != nil {
		return AuthorizedPassiveRun{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	result := AuthorizedPassiveRun{
		Observations: make([]Observation, 0, len(profile.Checks)),
		Decisions:    make([]PolicyDecision, 0, len(profile.Checks)),
		Usage:        usage,
	}
	seen := make(map[string]struct{}, len(profile.Checks))
	for _, check := range profile.Checks {
		runCheck := check
		if policy.MaxBytes > 0 {
			remaining := policy.MaxBytes - result.Usage.Bytes
			if remaining < runCheck.MaxBodyBytes {
				runCheck.MaxBodyBytes = remaining
			}
		}
		if runCheck.MaxBodyBytes <= 0 {
			result.Decisions = append(result.Decisions, PolicyDecision{Allowed: false, Reason: "byte budget exhausted"})
			result.Observations = append(result.Observations, Observation{ActionID: check.ID, Status: "denied", ErrorCode: "policy_denied", Summary: "byte budget exhausted", Redacted: true})
			continue
		}
		action, err := passiveAction(runCheck, authContext)
		if err != nil {
			return AuthorizedPassiveRun{}, err
		}
		decision := EvaluateAction(action, policy, result.Usage, approval, now)
		result.Decisions = append(result.Decisions, decision)
		if !decision.Allowed {
			result.Observations = append(result.Observations, Observation{
				ActionID:       check.ID,
				Status:         "denied",
				ErrorCode:      "policy_denied",
				Summary:        decision.Reason,
				Redacted:       true,
				ProvenanceNote: "policy_digest=" + decision.ActionDigest,
			})
			continue
		}
		observations := r.runVerified(ctx, PassiveProfile{Checks: []PassiveCheck{runCheck}}, authContext, &result.Usage, seen)
		result.Observations = append(result.Observations, observations...)
	}
	return result, nil
}

func passiveAction(check PassiveCheck, authContext string) (Action, error) {
	u, err := url.Parse(check.URL)
	if err != nil {
		return Action{}, err
	}
	args, err := json.Marshal(struct {
		Method          string            `json:"method"`
		URL             string            `json:"url"`
		Headers         map[string]string `json:"headers,omitempty"`
		MaxBodyBytes    int64             `json:"max_body_bytes"`
		TimeoutMS       int               `json:"timeout_ms"`
		FollowRedirects bool              `json:"follow_redirects"`
	}{strings.ToUpper(check.Method), check.URL, check.Headers, check.MaxBodyBytes, check.TimeoutMS, check.FollowRedirects})
	if err != nil {
		return Action{}, err
	}
	return Action{
		ID:             check.ID,
		Tool:           "http_request",
		Arguments:      args,
		TargetScope:    u.Host,
		Capability:     "http.read",
		TimeoutMS:      check.TimeoutMS,
		IdempotencyKey: PassiveRequestKey(check, authContext),
		ReadOnly:       true,
		Idempotent:     true,
	}, nil
}

func (r *PassiveRunner) runVerified(ctx context.Context, profile PassiveProfile, authContext string, usage *PolicyUsage, seen map[string]struct{}) []Observation {
	out := make([]Observation, 0, len(profile.Checks))
	for _, check := range profile.Checks {
		key := PassiveRequestKey(check, authContext)
		_, duplicate := seen[key]
		if !duplicate {
			seen[key] = struct{}{}
		}
		if duplicate {
			out = append(out, Observation{ActionID: check.ID, Status: "skipped", Summary: "duplicate request skipped", Redacted: true})
			continue
		}
		obs := r.runCheck(ctx, check)
		out = append(out, obs)
		if usage != nil {
			usage.Actions++
			usage.Bytes += obs.BytesStored
		}
	}
	return out
}

func (r *PassiveRunner) runCheck(ctx context.Context, check PassiveCheck) Observation {
	started := time.Now()
	obs := Observation{ActionID: check.ID, Status: "error"}
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(check.TimeoutMS)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, strings.ToUpper(check.Method), check.URL, nil)
	if err != nil {
		obs.ErrorCode = "invalid_request"
		obs.Summary = err.Error()
		obs.Duration = time.Since(started)
		return obs
	}
	for key, value := range check.Headers {
		req.Header.Set(key, value)
	}
	client := r.Client
	if base, ok := client.(*http.Client); ok {
		clone := *base
		originScheme, originHost := strings.ToLower(req.URL.Scheme), strings.ToLower(req.URL.Host)
		clone.CheckRedirect = func(next *http.Request, via []*http.Request) error {
			if !check.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) == 0 || strings.ToLower(next.URL.Scheme) != originScheme || strings.ToLower(next.URL.Host) != originHost {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return fmt.Errorf("redirect limit exceeded")
			}
			return nil
		}
		client = &clone
	}
	resp, err := client.Do(req)
	if err != nil {
		obs.ErrorCode = "request_failed"
		if requestCtx.Err() == context.DeadlineExceeded {
			obs.Status = "timeout"
			obs.ErrorCode = "timeout"
		}
		obs.Summary = err.Error()
		obs.Duration = time.Since(started)
		return obs
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, check.MaxBodyBytes+1)
	body, readErr := io.ReadAll(limited)
	obs.BytesRead = int64(len(body))
	if int64(len(body)) > check.MaxBodyBytes {
		obs.Truncated = true
		body = body[:check.MaxBodyBytes]
	}
	obs.BytesStored = int64(len(body))
	obs.Redacted = true
	if readErr != nil {
		obs.ErrorCode = "read_failed"
		obs.Summary = readErr.Error()
	} else if resp.StatusCode >= 300 {
		obs.Status = "error"
		if resp.StatusCode < 400 {
			obs.ErrorCode = "redirect_not_followed"
		}
		obs.Summary = fmt.Sprintf("HTTP %d; body_bytes=%d", resp.StatusCode, len(body))
	} else {
		obs.Status = "ok"
		obs.Summary = fmt.Sprintf("HTTP %d; body_bytes=%d", resp.StatusCode, len(body))
	}
	obs.ProvenanceNote = fmt.Sprintf("%s %s; status=%d; content_length=%d", req.Method, safePassiveURL(req.URL), resp.StatusCode, len(body))
	obs.Duration = time.Since(started)
	return obs
}

func safePassiveURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	copy := *u
	copy.RawQuery = ""
	copy.ForceQuery = false
	return copy.String()
}
