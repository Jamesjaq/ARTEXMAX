package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
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
