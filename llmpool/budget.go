package llmpool

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"

	"github.com/Autumn-27/norma/llm"
)

// Role identifies the purpose of a model call. Keeping roles explicit prevents
// an expensive reasoner from silently serving summarization or classification.
type Role string

const (
	RoleReasoner   Role = "reasoner"
	RoleSummarizer Role = "summarizer"
	RoleExtractor  Role = "extractor"
	RoleVerifier   Role = "verifier"
)

// Route is a role-specific provider group. The first non-nil group is used;
// callers can provide a fallback group explicitly instead of relying on an
// implicit cross-role fallback.
type Route struct {
	Groups map[Role]llm.Provider
}

func (r Route) Provider(role Role) (llm.Provider, error) {
	if p := r.Groups[role]; p != nil {
		return p, nil
	}
	return nil, fmt.Errorf("no provider route configured for role %q", role)
}

// Budget is a hard per-run or per-tenant budget. A zero limit is unlimited.
// Cost is expressed in microcurrency units per 1,000 billable tokens.
type Budget struct {
	MaxInputTokens   int
	MaxOutputTokens  int
	MaxTotalTokens   int
	MaxCostMicros    int64
	InputMicrosPerK  int64
	OutputMicrosPerK int64
}

// UsageLedger reserves request capacity before a provider call and commits the
// actual usage after completion. Reservations make concurrent workers fail
// closed instead of racing past a shared budget.
type UsageLedger struct {
	mu             sync.Mutex
	budget         Budget
	usage          llm.Usage
	costMicros     int64
	reservedInput  int
	reservedOutput int
}

type Reservation struct{ input, output int }

func NewUsageLedger(b Budget) *UsageLedger { return &UsageLedger{budget: b} }

func (l *UsageLedger) Snapshot() (llm.Usage, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.usage, l.costMicros
}

func (l *UsageLedger) Reserve(req llm.CompletionRequest, estimatedInput int) (Reservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	maxOut := req.MaxTokens
	if maxOut < 0 {
		maxOut = 0
	}
	candidate := l.usage
	candidate.InputTokens += l.reservedInput + estimatedInput
	candidate.OutputTokens += l.reservedOutput + maxOut
	if l.budget.MaxInputTokens > 0 && candidate.InputTokens > l.budget.MaxInputTokens {
		return Reservation{}, errors.New("LLM input-token budget exhausted")
	}
	if l.budget.MaxOutputTokens > 0 && candidate.OutputTokens > l.budget.MaxOutputTokens {
		return Reservation{}, errors.New("LLM output-token budget exhausted")
	}
	if l.budget.MaxTotalTokens > 0 && candidate.InputTokens+candidate.OutputTokens > l.budget.MaxTotalTokens {
		return Reservation{}, errors.New("LLM total-token budget exhausted")
	}
	l.reservedInput += estimatedInput
	l.reservedOutput += maxOut
	return Reservation{input: estimatedInput, output: maxOut}, nil
}

func (l *UsageLedger) Commit(res Reservation, u llm.Usage) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reservedInput -= res.input
	l.reservedOutput -= res.output
	candidate := l.usage
	candidate.Add(u)
	cost := estimateCost(candidate, l.budget)
	if l.budget.MaxCostMicros > 0 && cost > l.budget.MaxCostMicros {
		return errors.New("LLM cost budget exhausted")
	}
	l.usage = candidate
	l.costMicros = cost
	return nil
}

func (l *UsageLedger) Release(res Reservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reservedInput -= res.input
	l.reservedOutput -= res.output
}

func estimateCost(u llm.Usage, b Budget) int64 {
	return int64(u.InputTokens+u.CacheReadTokens+u.CacheWriteTokens)*b.InputMicrosPerK/1000 + int64(u.OutputTokens)*b.OutputMicrosPerK/1000
}

// BudgetedProvider applies a shared ledger to both streaming and non-streaming
// provider calls. Streaming is conservatively reserved at MaxTokens before the
// call so a failed stream cannot overspend a hard budget.
type BudgetedProvider struct {
	Provider      llm.Provider
	Ledger        *UsageLedger
	EstimateInput func(llm.CompletionRequest) int
}

func (p BudgetedProvider) estimate(req llm.CompletionRequest) int {
	if p.EstimateInput != nil {
		return p.EstimateInput(req)
	}
	return estimateRequestTokens(req)
}

func (p BudgetedProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if p.Provider == nil || p.Ledger == nil {
			yield(llm.StreamEvent{}, errors.New("budgeted provider is not configured"))
			return
		}
		reservation, err := p.Ledger.Reserve(req, p.estimate(req))
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		var last llm.Usage
		for ev, err := range p.Provider.Stream(ctx, req) {
			if ev.Usage.InputTokens+ev.Usage.OutputTokens+ev.Usage.CacheReadTokens+ev.Usage.CacheWriteTokens > 0 {
				last = ev.Usage
			}
			if !yield(ev, err) {
				p.Ledger.Release(reservation)
				return
			}
			if err != nil {
				p.Ledger.Release(reservation)
				return
			}
		}
		_ = p.Ledger.Commit(reservation, last)
	}
}

func (p BudgetedProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if p.Provider == nil || p.Ledger == nil {
		return llm.Message{}, "", llm.Usage{}, errors.New("budgeted provider is not configured")
	}
	reservation, err := p.Ledger.Reserve(req, p.estimate(req))
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	msg, stop, usage, err := p.Provider.Complete(ctx, req)
	if err != nil {
		p.Ledger.Release(reservation)
		return msg, stop, usage, err
	}
	if err := p.Ledger.Commit(reservation, usage); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	return msg, stop, usage, nil
}

func estimateRequestTokens(req llm.CompletionRequest) int {
	n := 0
	for _, s := range req.System {
		n += len(s)
	}
	for _, m := range req.Messages {
		for _, b := range m.Content {
			n += len(b.Text) + len(b.Input) + len(b.Name)
		}
	}
	return n * 2 / 7
}
