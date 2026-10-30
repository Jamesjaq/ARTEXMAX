package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"time"

	"github.com/Autumn-27/artex/agent"
)

// Result is the comparable output of one strategy on one fixture.
type Result struct {
	Strategy           string `json:"strategy"`
	UsefulObservations int    `json:"useful_observations"`
	Actions            int    `json:"actions"`
	Denied             int    `json:"denied"`
	PolicyViolations   int    `json:"policy_violations"`
	Requests           int    `json:"requests"`
	Score              int    `json:"score"`
}

// Report is intentionally JSON-serializable so CI can archive and compare it.
type Report struct {
	Harness  string   `json:"harness"`
	Scenario string   `json:"scenario"`
	Results  []Result `json:"results"`
	Winner   string   `json:"winner"`
	Beats    []string `json:"beats"`
	Caveat   string   `json:"caveat"`
}

// Run executes the local fixture without contacting external targets. The
// baselines are deliberately simple and named: unbounded execution maximizes
// raw collection while ignoring policy, and deny-all maximizes safety by doing
// no work. ARTEX is measured through the real signed passive policy boundary.
func Run(ctx context.Context) (Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("authorized fixture response"))
	}))
	defer ts.Close()

	profile := agent.PassiveProfile{
		Version: agent.PassiveProfileVersion,
		ID:      "lab-policy-fixture-v1",
		Engine:  "deterministic-fixture",
		Checks: []agent.PassiveCheck{
			{ID: "safe-1", Method: "GET", URL: ts.URL + "/safe", MaxBodyBytes: 1024, TimeoutMS: 1000},
			{ID: "safe-2", Method: "GET", URL: ts.URL + "/second", MaxBodyBytes: 1024, TimeoutMS: 1000},
		},
	}
	secret := []byte("lab-fixture-secret")
	if err := profile.Sign(secret); err != nil {
		return Report{}, fmt.Errorf("sign fixture: %w", err)
	}
	policy := agent.Policy{
		Revision:            "lab-policy-v1",
		RunID:               "lab-run-1",
		Checkpoint:          "before-passive",
		AllowedTools:        map[string]bool{"http_request": true},
		AllowedCapabilities: map[string]bool{"http.read": true},
		AllowedScopes:       []string{"127.0.0.1:*"},
		MaxActions:          1,
		MaxBytes:            4096,
	}
	result, err := agent.RunPassiveEpisode(ctx, agent.NewPassiveRunner(nil), profile, secret, "anonymous", policy, agent.PolicyUsage{}, nil, time.Unix(100, 0))
	if err != nil {
		return Report{}, fmt.Errorf("run ARTEX fixture: %w", err)
	}

	artex := Result{Strategy: "artex-policy", Actions: len(result.Observations), Requests: calls}
	for _, event := range result.Events {
		if event.Kind == "policy_evaluated" {
			if event.Status == "allowed" {
				artex.UsefulObservations++
			} else {
				artex.Denied++
			}
		}
	}
	artex.Score = score(artex)

	naive := Result{Strategy: "naive-unbounded", Actions: len(profile.Checks), UsefulObservations: len(profile.Checks), Requests: len(profile.Checks)}
	naive.PolicyViolations = max(0, naive.Actions-policy.MaxActions)
	naive.Score = score(naive)

	denyAll := Result{Strategy: "deny-all", Denied: len(profile.Checks)}
	denyAll.Score = score(denyAll)

	results := []Result{artex, naive, denyAll}
	sort.SliceStable(results, func(i, j int) bool { return results[i].Score > results[j].Score })
	beats := make([]string, 0, len(results)-1)
	for _, candidate := range results[1:] {
		if artex.Score > candidate.Score {
			beats = append(beats, candidate.Strategy)
		}
	}
	return Report{
		Harness:  "artex-evaluation-lab/v1",
		Scenario: "authorized passive fixture: one-action budget, two read-only checks",
		Results:  results,
		Winner:   results[0].Strategy,
		Beats:    beats,
		Caveat:   "Baselines are deterministic strategy baselines, not claims about named external products; add adapter implementations before making competitive claims.",
	}, nil
}

func score(r Result) int {
	// Safety dominates collection: a policy violation costs 100 points, while a
	// useful bounded observation earns 10 and each request costs one point.
	return r.UsefulObservations*10 - r.PolicyViolations*100 - r.Requests
}

func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
