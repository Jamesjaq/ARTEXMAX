package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PassiveRunner executes only validated passive profiles. It keeps request
// deduplication local to one run so repeated checks cannot amplify traffic.
type PassiveRunner struct {
	Client httpDoer
	mu     sync.Mutex
	seen   map[string]struct{}
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func NewPassiveRunner(client httpDoer) *PassiveRunner {
	if client == nil {
		client = &http.Client{}
	}
	return &PassiveRunner{Client: client, seen: make(map[string]struct{})}
}

func (r *PassiveRunner) Run(ctx context.Context, profile PassiveProfile, secret []byte, authContext string) ([]Observation, error) {
	if err := profile.Verify(secret); err != nil {
		return nil, err
	}
	out := make([]Observation, 0, len(profile.Checks))
	for _, check := range profile.Checks {
		key := PassiveRequestKey(check, authContext)
		r.mu.Lock()
		_, duplicate := r.seen[key]
		if !duplicate {
			r.seen[key] = struct{}{}
		}
		r.mu.Unlock()
		if duplicate {
			continue
		}
		obs := r.runCheck(ctx, check)
		out = append(out, obs)
	}
	return out, nil
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
	if base, ok := client.(*http.Client); ok && !check.FollowRedirects {
		clone := *base
		clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
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
	obs.ProvenanceNote = fmt.Sprintf("%s %s; status=%d; content_length=%d", req.Method, req.URL.String(), resp.StatusCode, len(body))
	obs.Duration = time.Since(started)
	return obs
}
