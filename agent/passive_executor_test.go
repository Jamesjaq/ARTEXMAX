package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPassiveRunnerExecutesBoundedDeduplicatedChecks(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer ts.Close()
	p := PassiveProfile{Version: PassiveProfileVersion, ID: "fixture", Engine: "test", Checks: []PassiveCheck{{ID: "a", Method: "GET", URL: ts.URL, MaxBodyBytes: 4, TimeoutMS: 1000}}}
	if err := p.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	obs, err := NewPassiveRunner(nil).Run(context.Background(), p, []byte("secret"), "anonymous")
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || !obs[0].Truncated || obs[0].BytesStored != 4 {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want 1", calls)
	}
}

func TestPassiveRunnerRejectsRedirectWhenDisabled(t *testing.T) {
	redirect := httptest.NewServer(http.RedirectHandler("/final", http.StatusFound))
	defer redirect.Close()
	p := PassiveProfile{Version: PassiveProfileVersion, ID: "redirect", Engine: "test", Checks: []PassiveCheck{{ID: "r", Method: "GET", URL: redirect.URL, MaxBodyBytes: 64, TimeoutMS: 1000, FollowRedirects: false}}}
	if err := p.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	obs, err := NewPassiveRunner(nil).Run(context.Background(), p, []byte("secret"), "anonymous")
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Status != "error" {
		t.Fatalf("unexpected redirect observation: %+v", obs)
	}
}

func TestPassiveRunnerPolicyDenialIsFailClosed(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer ts.Close()
	p := PassiveProfile{Version: PassiveProfileVersion, ID: "denied", Engine: "test", Checks: []PassiveCheck{{ID: "a", Method: "GET", URL: ts.URL, MaxBodyBytes: 64, TimeoutMS: 1000}}}
	if err := p.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	result, err := NewPassiveRunner(nil).RunAuthorized(context.Background(), p, []byte("secret"), "anonymous", Policy{
		Revision:            "r1",
		AllowedTools:        map[string]bool{"http_request": true},
		AllowedCapabilities: map[string]bool{"http.read": true},
		AllowedScopes:       []string{"other.example"},
	}, PolicyUsage{}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 1 || result.Observations[0].Status != "denied" || result.Decisions[0].Allowed {
		t.Fatalf("unexpected denial result: %+v", result)
	}
	if calls != 0 {
		t.Fatalf("denied request reached server: calls=%d", calls)
	}
}

func TestPassiveRunnerPolicyAllowsExactAction(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	check := PassiveCheck{ID: "a", Method: "GET", URL: ts.URL, MaxBodyBytes: 64, TimeoutMS: 1000}
	p := PassiveProfile{Version: PassiveProfileVersion, ID: "allowed", Engine: "test", Checks: []PassiveCheck{check}}
	if err := p.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Revision: "r1", AllowedTools: map[string]bool{"http_request": true}, AllowedCapabilities: map[string]bool{"http.read": true}, AllowedScopes: []string{"127.0.0.1:*"}, MaxActions: 1}
	result, err := NewPassiveRunner(nil).RunAuthorized(context.Background(), p, []byte("secret"), "anonymous", policy, PolicyUsage{}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 1 || result.Observations[0].Status != "error" && result.Observations[0].Status != "ok" {
		t.Fatalf("unexpected observation: %+v", result.Observations)
	}
	if len(result.Decisions) != 1 || !result.Decisions[0].Allowed || calls != 1 || result.Usage.Actions != 1 {
		t.Fatalf("unexpected authorization result: %+v calls=%d", result, calls)
	}
}

func TestPassiveRunnerDeduplicatesWithinRunButNotAcrossRuns(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()
	checkA := PassiveCheck{ID: "a", Method: "GET", URL: ts.URL, MaxBodyBytes: 16, TimeoutMS: 1000}
	checkB := checkA
	checkB.ID = "b"
	p := PassiveProfile{Version: PassiveProfileVersion, ID: "duplicates", Engine: "test", Checks: []PassiveCheck{checkA, checkB}}
	if err := p.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Revision: "r1", AllowedTools: map[string]bool{"http_request": true}, AllowedCapabilities: map[string]bool{"http.read": true}, AllowedScopes: []string{"127.0.0.1:*"}}
	runner := NewPassiveRunner(nil)
	result, err := runner.RunAuthorized(context.Background(), p, []byte("secret"), "anonymous", policy, PolicyUsage{}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(result.Observations) != 2 || result.Observations[1].Status != "skipped" {
		t.Fatalf("same-run dedupe failed: calls=%d observations=%+v", calls, result.Observations)
	}
	if _, err := runner.RunAuthorized(context.Background(), p, []byte("secret"), "anonymous", policy, PolicyUsage{}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("runner leaked dedupe state across runs: calls=%d, want 2", calls)
	}
}

func TestPassiveRunnerEnforcesCumulativeByteBudget(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer ts.Close()
	checks := []PassiveCheck{
		{ID: "a", Method: "GET", URL: ts.URL, MaxBodyBytes: 8, TimeoutMS: 1000},
		{ID: "b", Method: "GET", URL: ts.URL + "/second", MaxBodyBytes: 8, TimeoutMS: 1000},
	}
	p := PassiveProfile{Version: PassiveProfileVersion, ID: "byte-budget", Engine: "test", Checks: checks}
	if err := p.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Revision: "r1", AllowedTools: map[string]bool{"http_request": true}, AllowedCapabilities: map[string]bool{"http.read": true}, AllowedScopes: []string{"127.0.0.1:*"}, MaxBytes: 5}
	result, err := NewPassiveRunner(nil).RunAuthorized(context.Background(), p, []byte("secret"), "anonymous", policy, PolicyUsage{}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || result.Usage.Bytes != 5 || len(result.Observations) != 2 || result.Observations[0].BytesStored != 5 || result.Observations[1].Status != "denied" {
		t.Fatalf("byte budget was not enforced: calls=%d usage=%+v observations=%+v", calls, result.Usage, result.Observations)
	}
}

func TestPassiveRunnerBlocksCrossOriginRedirect(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationCalls++
		_, _ = w.Write([]byte("must not be fetched"))
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusFound)
	}))
	defer origin.Close()
	p := PassiveProfile{Version: PassiveProfileVersion, ID: "redirect-scope", Engine: "test", Checks: []PassiveCheck{{ID: "r", Method: "GET", URL: origin.URL, MaxBodyBytes: 64, TimeoutMS: 1000, FollowRedirects: true}}}
	if err := p.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	obs, err := NewPassiveRunner(nil).Run(context.Background(), p, []byte("secret"), "anonymous")
	if err != nil {
		t.Fatal(err)
	}
	if destinationCalls != 0 || len(obs) != 1 || obs[0].Status != "error" || obs[0].ErrorCode != "redirect_not_followed" {
		t.Fatalf("cross-origin redirect was followed: destination calls=%d observations=%+v", destinationCalls, obs)
	}
}
