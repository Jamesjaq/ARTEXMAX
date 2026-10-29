package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	PassiveProfileVersion = 1
	MaxPassiveChecks      = 256
	MaxPassiveBodyBytes   = 1 << 20
	MaxPassiveTimeoutMS   = 30_000
)

// PassiveProfile is the only profile shape accepted by the low-impact HTTP
// checker. Its signature covers every field except Signature.
type PassiveProfile struct {
	Version   int            `json:"version"`
	ID        string         `json:"id"`
	Engine    string         `json:"engine"`
	Checks    []PassiveCheck `json:"checks"`
	Signature string         `json:"signature"`
}

type PassiveCheck struct {
	ID              string            `json:"id"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	MaxBodyBytes    int64             `json:"max_body_bytes"`
	TimeoutMS       int               `json:"timeout_ms"`
	FollowRedirects bool              `json:"follow_redirects"`
}

func (p PassiveProfile) Validate() error {
	if p.Version != PassiveProfileVersion {
		return fmt.Errorf("unsupported passive profile version %d", p.Version)
	}
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.Engine) == "" {
		return errors.New("profile id and engine are required")
	}
	if len(p.Checks) == 0 || len(p.Checks) > MaxPassiveChecks {
		return fmt.Errorf("profile must contain 1-%d checks", MaxPassiveChecks)
	}
	seen := make(map[string]struct{}, len(p.Checks))
	for _, c := range p.Checks {
		if strings.TrimSpace(c.ID) == "" {
			return errors.New("check id is required")
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate check id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		method := strings.ToUpper(strings.TrimSpace(c.Method))
		if method != "GET" && method != "HEAD" && method != "OPTIONS" {
			return fmt.Errorf("method %q is not passive", c.Method)
		}
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return fmt.Errorf("check %q has an unsafe URL", c.ID)
		}
		if c.MaxBodyBytes <= 0 || c.MaxBodyBytes > MaxPassiveBodyBytes {
			return fmt.Errorf("check %q body cap is outside bounds", c.ID)
		}
		if c.TimeoutMS <= 0 || c.TimeoutMS > MaxPassiveTimeoutMS {
			return fmt.Errorf("check %q timeout is outside bounds", c.ID)
		}
		for key := range c.Headers {
			if strings.EqualFold(key, "authorization") || strings.EqualFold(key, "cookie") || strings.EqualFold(key, "proxy-authorization") {
				return fmt.Errorf("check %q cannot include credential header %q", c.ID, key)
			}
		}
	}
	return nil
}

func (p PassiveProfile) unsignedBytes() []byte {
	clone := p
	clone.Signature = ""
	raw, _ := json.Marshal(clone)
	return raw
}

func (p *PassiveProfile) Sign(secret []byte) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if len(secret) == 0 {
		return errors.New("signing secret is required")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(p.unsignedBytes())
	p.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

func (p PassiveProfile) Verify(secret []byte) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if len(secret) == 0 || strings.TrimSpace(p.Signature) == "" {
		return errors.New("profile signature is missing")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(p.unsignedBytes())
	got, err := hex.DecodeString(p.Signature)
	if err != nil || !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("profile signature is invalid")
	}
	return nil
}

// PassiveRequestKey deduplicates only equivalent requests. Auth/session
// context is supplied separately so two requests to the same URL with
// different credentials do not collapse into one observation.
func PassiveRequestKey(check PassiveCheck, authContext string) string {
	headers := make([][2]string, 0, len(check.Headers))
	for k, v := range check.Headers {
		headers = append(headers, [2]string{strings.ToLower(k), v})
	}
	sort.Slice(headers, func(i, j int) bool {
		if headers[i][0] == headers[j][0] {
			return headers[i][1] < headers[j][1]
		}
		return headers[i][0] < headers[j][0]
	})
	canonical := struct {
		Method, URL, Auth string
		Headers           [][2]string
	}{strings.ToUpper(check.Method), check.URL, authContext, headers}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
