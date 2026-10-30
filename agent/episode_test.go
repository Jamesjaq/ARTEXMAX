package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunPassiveEpisodeProducesReplayableEvents(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	profile := PassiveProfile{Version: PassiveProfileVersion, ID: "episode", Engine: "fixture", Checks: []PassiveCheck{{ID: "check-1", Method: "GET", URL: ts.URL, MaxBodyBytes: 64, TimeoutMS: 1000}}}
	if err := profile.Sign([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Revision: "p1", AllowedTools: map[string]bool{"http_request": true}, AllowedCapabilities: map[string]bool{"http.read": true}, AllowedScopes: []string{"127.0.0.1:*"}, MaxActions: 1}
	result, err := RunPassiveEpisode(context.Background(), NewPassiveRunner(nil), profile, []byte("secret"), "anonymous", policy, PolicyUsage{}, nil, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || len(result.Events) != 3 || calls != 1 {
		t.Fatalf("result=%+v calls=%d", result, calls)
	}
	if result.Events[0].Kind != "policy_evaluated" || result.Events[0].Status != "allowed" {
		t.Fatalf("events=%+v", result.Events)
	}
	if result.Events[1].Kind != "observation_recorded" || result.Events[2].Status != "completed" {
		t.Fatalf("events=%+v", result.Events)
	}
}
