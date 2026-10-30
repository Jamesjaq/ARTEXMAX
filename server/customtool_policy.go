package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	actool "github.com/Autumn-27/norma/tool"
)

// CustomToolAuthorization is the execution-time authorization supplied by the
// control plane. A missing authorization is deliberately fail-closed.
type CustomToolAuthorization struct {
	Policy   agent.Policy
	Usage    agent.PolicyUsage
	Approval *agent.Approval
	Now      time.Time
}

type customToolAuthorizationKey struct{}

// WithCustomToolAuthorization attaches a policy snapshot to a custom-tool
// execution context. The snapshot is evaluated immediately before the process
// or HTTP client is touched.
func WithCustomToolAuthorization(ctx context.Context, authorization CustomToolAuthorization) context.Context {
	return context.WithValue(ctx, customToolAuthorizationKey{}, authorization)
}

func customToolAuthorization(ctx context.Context, action agent.Action) (agent.PolicyDecision, error) {
	value := ctx.Value(customToolAuthorizationKey{})
	authorization, ok := value.(CustomToolAuthorization)
	if !ok {
		return agent.PolicyDecision{}, fmt.Errorf("custom tool execution denied: no policy authorization")
	}
	if err := authorization.Policy.Validate(); err != nil {
		return agent.PolicyDecision{}, fmt.Errorf("custom tool execution denied: invalid policy: %w", err)
	}
	now := authorization.Now
	if now.IsZero() {
		now = time.Now()
	}
	decision := agent.EvaluateAction(action, authorization.Policy, authorization.Usage, authorization.Approval, now)
	if !decision.Allowed {
		return decision, fmt.Errorf("custom tool execution denied: %s", decision.Reason)
	}
	return decision, nil
}

func customToolAction(key, kind string, execRaw json.RawMessage, params map[string]any) (agent.Action, error) {
	if strings.TrimSpace(key) == "" {
		return agent.Action{}, fmt.Errorf("custom tool key is required")
	}
	args, err := json.Marshal(params)
	if err != nil {
		return agent.Action{}, err
	}
	specDigest := sha256.Sum256(execRaw)
	actionArguments, err := json.Marshal(struct {
		Parameters         json.RawMessage `json:"parameters"`
		ExecutorSpecSHA256 string          `json:"executor_spec_sha256"`
	}{args, hex.EncodeToString(specDigest[:])})
	if err != nil {
		return agent.Action{}, err
	}
	capability := "custom." + kind
	target := "local"
	readOnly, idempotent := false, false
	if kind == "http" {
		var spec httpExec
		if err := json.Unmarshal(execRaw, &spec); err != nil {
			return agent.Action{}, fmt.Errorf("invalid http exec spec: %w", err)
		}
		rawURL := renderTemplate(spec.URL, params, identity)
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			return agent.Action{}, fmt.Errorf("invalid http target")
		}
		target = u.Host
		method := strings.ToUpper(strings.TrimSpace(spec.Method))
		readOnly = method == "" || method == "GET" || method == "HEAD" || method == "OPTIONS"
		idempotent = readOnly || method == "PUT" || method == "DELETE"
		capability = "http." + strings.ToLower(method)
	}
	hashInput := make([]byte, 0, len(key)+len(kind)+len(execRaw)+len(args)+3)
	hashInput = append(hashInput, key...)
	hashInput = append(hashInput, ':')
	hashInput = append(hashInput, kind...)
	hashInput = append(hashInput, ':')
	hashInput = append(hashInput, execRaw...)
	hashInput = append(hashInput, ':')
	hashInput = append(hashInput, args...)
	hash := sha256.Sum256(hashInput)
	return agent.Action{
		ID:             key,
		Tool:           key,
		Arguments:      actionArguments,
		TargetScope:    target,
		Capability:     capability,
		TimeoutMS:      customToolTimeoutMS(kind, execRaw),
		IdempotencyKey: hex.EncodeToString(hash[:]),
		ReadOnly:       readOnly,
		Destructive:    !readOnly,
		Idempotent:     idempotent,
	}, nil
}

func customToolTimeoutMS(kind string, execRaw json.RawMessage) int {
	var timeout int
	switch kind {
	case "http":
		var spec httpExec
		_ = json.Unmarshal(execRaw, &spec)
		timeout = spec.TimeoutMs
	case "script":
		var spec scriptExec
		_ = json.Unmarshal(execRaw, &spec)
		timeout = spec.TimeoutMs
	default:
		var spec commandExec
		_ = json.Unmarshal(execRaw, &spec)
		timeout = spec.TimeoutMs
	}
	if timeout <= 0 {
		if kind == "http" {
			return 30000
		}
		return 120000
	}
	return timeout
}

var sensitiveOutputRE = regexp.MustCompile(`(?i)("(?:authorization|cookie|password|secret|token|api[_-]?key)"\s*:\s*")(.*?)(")`)

// normalizeCustomOutput bounds output through Norma's Capture and removes
// common credential-shaped JSON fields before exposing it to the model.
func normalizeCustomOutput(tc *actool.ToolContext, output string) string {
	redacted := redactCustomOutput(output)
	return actool.Capture(tc, redacted)
}

func redactCustomOutput(output string) string {
	return sensitiveOutputRE.ReplaceAllString(output, `${1}[REDACTED]${3}`)
}

func customToolError(tc *actool.ToolContext, err error) actool.Result {
	return actool.Text(normalizeCustomOutput(tc, err.Error()))
}
