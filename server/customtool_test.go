package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestRenderTemplateCommand(t *testing.T) {
	// command: string params shell-quoted; array → JSON (also quoted).
	got := renderTemplate("nmap -p {ports} {target}", map[string]any{
		"target": "10.0.0.1; rm -rf /", // injection attempt → must be single-quoted
		"ports":  []any{80.0, 443.0},
	}, shellQuote)
	if !strings.Contains(got, `'10.0.0.1; rm -rf /'`) {
		t.Fatalf("target not shell-quoted: %q", got)
	}
	if strings.Contains(got, "rm -rf /'") && !strings.Contains(got, `'10.0.0.1; rm -rf /'`) {
		t.Fatalf("possible injection leak: %q", got)
	}
	if strings.Contains(got, "{target}") || strings.Contains(got, "{ports}") {
		t.Fatalf("placeholders not replaced: %q", got)
	}
}

func TestRenderTemplateHTTP(t *testing.T) {
	// http: identity (no shell quoting) — raw substitution into url/body.
	got := renderTemplate("https://x/submit?flag={flag}", map[string]any{"flag": "CTF{abc}"}, identity)
	if got != "https://x/submit?flag=CTF{abc}" {
		t.Fatalf("http render: %q", got)
	}
}

func TestScalarStr(t *testing.T) {
	cases := []struct {
		v    any
		want string
		ok   bool
	}{
		{"hi", "hi", true},
		{true, "true", true},
		{float64(80), "80", true},   // integer-valued float → no decimal
		{float64(1.5), "1.5", true}, // real float
		{[]any{1, 2}, "", false},    // array → not scalar
		{map[string]any{}, "", false},
	}
	for _, c := range cases {
		got, ok := scalarStr(c.v)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("scalarStr(%v) = (%q,%v), want (%q,%v)", c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestEnsureSchema(t *testing.T) {
	// empty → thin {args:string}
	m := ensureSchema(nil)
	props, _ := m["properties"].(map[string]any)
	if _, ok := props["args"]; !ok {
		t.Fatalf("empty schema should default to args: %v", m)
	}
	// non-empty → passthrough
	raw := json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"}}}`)
	m2 := ensureSchema(raw)
	p2, _ := m2["properties"].(map[string]any)
	if _, ok := p2["target"]; !ok {
		t.Fatalf("non-empty schema should pass through: %v", m2)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Fatalf("shellQuote(a'b) = %q", got)
	}
}

// TestExecPython runs a real Python script end-to-end: it must read params from
// stdin JSON and the mirrored env var, then print — verifying the whole script
// param-passing path. Skips if no python3.
func TestExecPython(t *testing.T) {
	interp, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	code := `import json,sys,os
a = json.load(sys.stdin)
print("stdin_target=" + a["target"])
print("env_target=" + os.environ.get("TOOL_TARGET",""))
print("port=" + str(a["port"]))
`
	out, err := execPython(context.Background(), interp, "test", code,
		map[string]any{"target": "example.com", "port": float64(8080)},
		t.TempDir(), nil, 10*time.Second)
	if err != nil {
		t.Fatalf("execPython error: %v", err)
	}
	for _, want := range []string{"stdin_target=example.com", "env_target=example.com", "port=8080"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

// TestRunHTTPTool functionally exercises the http executor against a local server:
// method/url/header/body templates are rendered from params, the request is sent,
// and the response status+body are returned. No recording proxy → s.m untouched.
func TestRunHTTPTool(t *testing.T) {
	var gotMethod, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{
		"method":  "POST",
		"url":     srv.URL + "/submit?flag={flag}",
		"headers": map[string]string{"Authorization": "Bearer {token}"},
		"body":    `{"flag":"{flag}"}`,
	})
	res, err := (&Server{}).runHTTPTool(context.Background(), execRaw,
		map[string]any{"flag": "CTF{x}", "token": "sekret"}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	var out struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	_ = json.Unmarshal([]byte(res.Content[0].Text), &out)

	if gotMethod != "POST" {
		t.Fatalf("method: %q", gotMethod)
	}
	if gotAuth != "Bearer sekret" {
		t.Fatalf("header template not rendered: %q", gotAuth)
	}
	if gotBody != `{"flag":"CTF{x}"}` {
		t.Fatalf("body template not rendered: %q", gotBody)
	}
	if out.Status != 201 || !strings.Contains(out.Body, `"ok":true`) {
		t.Fatalf("response not captured: %+v", out)
	}
}

func TestDetectPython(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	if p := detectPython(); p == "" {
		t.Fatal("detectPython returned empty despite python3 on PATH")
	}
}

// The http tool must truncate an oversized response through norma's Capture, the
// same valve every other tool uses — a session with no OutputDir falls back to a
// head+tail cut, so a body far past the default cap comes back shortened.
func TestHTTPToolTruncatesLargeBody(t *testing.T) {
	big := strings.Repeat("x", 40000) // past Capture's 30000 default
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL})
	res, err := (&Server{}).runHTTPTool(context.Background(), execRaw, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	out := res.Flatten()
	if len(out) >= 40000 {
		t.Fatalf("oversized http body was not truncated: len=%d", len(out))
	}
}

func customToolTestAuth(tool, capability, scope string) CustomToolAuthorization {
	return CustomToolAuthorization{Policy: agent.Policy{
		Revision:            "test-policy",
		AllowedTools:        map[string]bool{tool: true},
		AllowedCapabilities: map[string]bool{capability: true},
		AllowedScopes:       []string{scope},
		MaxActions:          1,
		MaxBytes:            1 << 20,
	}}
}

func TestCustomToolActionDigestBindsExecutorSpec(t *testing.T) {
	params := map[string]any{"target": "example.test"}
	first, err := customToolAction("probe", "command", json.RawMessage(`{"command":"curl {target}"}`), params)
	if err != nil {
		t.Fatal(err)
	}
	second, err := customToolAction("probe", "command", json.RawMessage(`{"command":"curl {target}; touch /tmp/changed"}`), params)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := agent.ActionDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := agent.ActionDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Fatal("changing the executor command did not change the approval digest")
	}
	if first.IdempotencyKey == second.IdempotencyKey {
		t.Fatal("changing the executor command did not change the idempotency key")
	}
}

func TestCustomHTTPToolDeniedBeforeNetwork(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer srv.Close()
	tool := (&Server{}).buildCustomTool(&db.Tool{Key: "probe_http", Kind: "http", Exec: json.RawMessage(`{"method":"GET","url":"` + srv.URL + `"}`)})
	res, err := tool.Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "no policy authorization") {
		t.Fatalf("expected fail-closed denial, got %+v", res)
	}
	if calls != 0 {
		t.Fatalf("denied HTTP tool executed %d requests", calls)
	}
}

func TestCustomHTTPToolAllowedAndRedactsOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"token":"do-not-leak"}`))
	}))
	defer srv.Close()
	spec := json.RawMessage(`{"method":"GET","url":"` + srv.URL + `","timeout_ms":1000}`)
	tool := (&Server{}).buildCustomTool(&db.Tool{Key: "probe_http", Kind: "http", Exec: spec})
	u, _ := url.Parse(srv.URL)
	ctx := WithCustomToolAuthorization(context.Background(), customToolTestAuth("probe_http", "http.get", u.Host))
	res, err := tool.Call(ctx, json.RawMessage(`{}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("allowed HTTP tool failed: %v %+v", err, res)
	}
	if strings.Contains(res.Flatten(), "do-not-leak") || !strings.Contains(res.Flatten(), "[REDACTED]") {
		t.Fatalf("HTTP output was not normalized/redacted: %q", res.Flatten())
	}
}

func TestCustomScriptToolDeniedBeforeInterpreter(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}}
	spec := json.RawMessage(`{"code":"raise SystemExit('must not run')","timeout_ms":1000}`)
	tool := s.buildCustomTool(&db.Tool{Key: "probe_script", Kind: "script", Exec: spec})
	res, err := tool.Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "no policy authorization") {
		t.Fatalf("expected fail-closed script denial, got %+v", res)
	}
	if strings.Contains(res.Flatten(), "must not run") {
		t.Fatal("denied script produced execution output")
	}
}

func TestCustomScriptToolAllowedBoundedAndRedactsOutput(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	s := &Server{m: &Manager{dir: t.TempDir()}}
	spec := json.RawMessage(`{"code":"print('{\"token\":\"do-not-leak\",\"ok\":true}')","timeout_ms":1000}`)
	tool := s.buildCustomTool(&db.Tool{Key: "probe_script", Kind: "script", Exec: spec})
	ctx := WithCustomToolAuthorization(context.Background(), customToolTestAuth("probe_script", "custom.script", "local"))
	res, err := tool.Call(ctx, json.RawMessage(`{}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("allowed script tool failed: %v %+v", err, res)
	}
	if strings.Contains(res.Flatten(), "do-not-leak") || !strings.Contains(res.Flatten(), "[REDACTED]") {
		t.Fatalf("script output was not normalized/redacted: %q", res.Flatten())
	}
}
