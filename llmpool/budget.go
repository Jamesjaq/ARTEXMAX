package llmpool

import (
	"context"
	"encoding/json"
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

// Budget is a hard per-run or per-tenant budget. A zero cumulative limit is
// unlimited. MaxOutputPerCallTokens caps any otherwise-uncapped call; when a
// cumulative output, total-token, or cost limit is configured, uncapped requests
// fail closed unless this per-call cap is set.
// Cost is expressed in microcurrency units per 1,000 billable tokens.
type Budget struct {
	MaxInputTokens         int
	MaxOutputTokens        int
	MaxTotalTokens         int
	MaxOutputPerCallTokens int
	MaxCostMicros          int64
	InputMicrosPerK        int64
	OutputMicrosPerK       int64
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
	reservedCost   int64
}

type Reservation struct {
	input, output int
	costMicros    int64
	maxTokens     int
}

func NewUsageLedger(b Budget) *UsageLedger { return &UsageLedger{budget: b} }

func (l *UsageLedger) Snapshot() (llm.Usage, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.usage, l.costMicros
}

// Reserve applies all currently known limits and returns the effective output
// cap that must be sent to the provider. estimatedInput must include the whole
// request (system prompt, messages, and tool schemas), not only message text.
func (l *UsageLedger) Reserve(req llm.CompletionRequest, estimatedInput int) (Reservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if estimatedInput < 0 {
		return Reservation{}, errors.New("estimated input tokens cannot be negative")
	}

	maxOut := req.MaxTokens
	if maxOut < 0 {
		maxOut = 0
	}
	if l.budget.MaxOutputPerCallTokens > 0 && (maxOut == 0 || maxOut > l.budget.MaxOutputPerCallTokens) {
		maxOut = l.budget.MaxOutputPerCallTokens
	}
	hardOutputBudget := l.budget.MaxOutputTokens > 0 || l.budget.MaxTotalTokens > 0 || l.budget.MaxCostMicros > 0
	if maxOut == 0 && hardOutputBudget {
		return Reservation{}, errors.New("uncapped request cannot be enforced by the configured output, total-token, or cost budget")
	}

	inputUsed := inputTokens(l.usage) + l.reservedInput + estimatedInput
	if l.budget.MaxInputTokens > 0 && inputUsed > l.budget.MaxInputTokens {
		return Reservation{}, errors.New("LLM input-token budget exhausted")
	}
	if l.budget.MaxOutputTokens > 0 {
		remaining := l.budget.MaxOutputTokens - l.usage.OutputTokens - l.reservedOutput
		if remaining <= 0 {
			return Reservation{}, errors.New("LLM output-token budget exhausted")
		}
		maxOut = minPositive(maxOut, remaining)
	}
	if l.budget.MaxTotalTokens > 0 {
		remaining := l.budget.MaxTotalTokens - inputUsed - l.usage.OutputTokens - l.reservedOutput
		if remaining <= 0 {
			return Reservation{}, errors.New("LLM total-token budget exhausted")
		}
		maxOut = minPositive(maxOut, remaining)
	}
	if l.budget.MaxCostMicros > 0 {
		if l.budget.InputMicrosPerK <= 0 || l.budget.OutputMicrosPerK <= 0 {
			return Reservation{}, errors.New("LLM cost budget has no usable pricing rates")
		}
		remainingCost := l.budget.MaxCostMicros - l.costMicros - l.reservedCost - estimateCost(llm.Usage{InputTokens: estimatedInput}, l.budget)
		if remainingCost <= 0 {
			return Reservation{}, errors.New("LLM cost budget exhausted")
		}
		maxOut = minPositive(maxOut, affordableOutputTokens(remainingCost, l.budget.OutputMicrosPerK))
	}
	if maxOut <= 0 && hardOutputBudget {
		return Reservation{}, errors.New("LLM output budget exhausted")
	}

	reservedCost := estimateCost(llm.Usage{InputTokens: estimatedInput, OutputTokens: maxOut}, l.budget)
	l.reservedInput += estimatedInput
	l.reservedOutput += maxOut
	l.reservedCost += reservedCost
	return Reservation{input: estimatedInput, output: maxOut, costMicros: reservedCost, maxTokens: maxOut}, nil
}

// Commit records actual usage even when it exceeded the reservation. Callers
// receive an error after the usage is retained so accounting never hides a real
// provider overrun.
func (l *UsageLedger) Commit(res Reservation, u llm.Usage) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reservedInput -= res.input
	l.reservedOutput -= res.output
	l.reservedCost -= res.costMicros
	candidate := l.usage
	candidate.Add(u)
	cost := estimateCost(candidate, l.budget)
	l.usage = candidate
	l.costMicros = cost
	return l.checkCommittedBudget(candidate, cost)
}

// CommitPartial records usage observed before a consumer abandons a stream,
// while retaining the unobserved portion of the reservation. The provider may
// have generated or billed for output that was never delivered to this consumer;
// that remainder stays reserved until the per-run ledger is discarded.
func (l *UsageLedger) CommitPartial(res Reservation, u llm.Usage) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	remainingInput := max(0, res.input-inputTokens(u))
	remainingOutput := max(0, res.output-u.OutputTokens)
	remainingCost := max(int64(0), res.costMicros-estimateCost(u, l.budget))
	l.reservedInput += remainingInput - res.input
	l.reservedOutput += remainingOutput - res.output
	l.reservedCost += remainingCost - res.costMicros
	candidate := l.usage
	candidate.Add(u)
	l.usage = candidate
	l.costMicros = estimateCost(candidate, l.budget)
	return l.checkCommittedBudget(candidate, l.costMicros)
}

func (l *UsageLedger) Release(res Reservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reservedInput -= res.input
	l.reservedOutput -= res.output
	l.reservedCost -= res.costMicros
}

func (l *UsageLedger) checkCommittedBudget(candidate llm.Usage, cost int64) error {
	if l.budget.MaxInputTokens > 0 && inputTokens(candidate)+l.reservedInput > l.budget.MaxInputTokens {
		return errors.New("LLM input-token budget exceeded by actual provider usage; usage was recorded")
	}
	if l.budget.MaxOutputTokens > 0 && candidate.OutputTokens+l.reservedOutput > l.budget.MaxOutputTokens {
		return errors.New("LLM output-token budget exceeded by actual provider usage; usage was recorded")
	}
	if l.budget.MaxTotalTokens > 0 && inputTokens(candidate)+candidate.OutputTokens+l.reservedInput+l.reservedOutput > l.budget.MaxTotalTokens {
		return errors.New("LLM total-token budget exceeded by actual provider usage; usage was recorded")
	}
	if l.budget.MaxCostMicros > 0 && cost+l.reservedCost > l.budget.MaxCostMicros {
		return errors.New("LLM cost budget exceeded by actual provider usage; usage was recorded")
	}
	return nil
}

func inputTokens(u llm.Usage) int {
	return max(0, u.InputTokens) + max(0, u.CacheReadTokens) + max(0, u.CacheWriteTokens)
}

func minPositive(a, b int) int {
	if a <= 0 || b < a {
		return b
	}
	return a
}

func affordableOutputTokens(micros, outputMicrosPerK int64) int {
	if micros <= 0 || outputMicrosPerK <= 0 {
		return 0
	}
	maxInt64 := int64(^uint64(0) >> 1)
	if micros > maxInt64/1000 {
		return int(^uint(0) >> 1)
	}
	tokens := micros * 1000 / outputMicrosPerK
	maxInt := int(^uint(0) >> 1)
	if tokens > int64(maxInt) {
		return maxInt
	}
	return int(tokens)
}

func estimateCost(u llm.Usage, b Budget) int64 {
	return int64(inputTokens(u))*b.InputMicrosPerK/1000 + int64(max(0, u.OutputTokens))*b.OutputMicrosPerK/1000
}

// BudgetedProvider applies a shared ledger to both streaming and non-streaming
// provider calls. Output is capped at the reservation before the request reaches
// the provider; actual usage is recorded and checked on completion.
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

func requestWithReservation(req llm.CompletionRequest, reservation Reservation) llm.CompletionRequest {
	if reservation.maxTokens > 0 {
		req.MaxTokens = reservation.maxTokens
	}
	return req
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
		req = requestWithReservation(req, reservation)
		var total llm.Usage
		for ev, err := range p.Provider.Stream(ctx, req) {
			total.Add(ev.Usage)
			if !yield(ev, err) {
				_ = p.Ledger.CommitPartial(reservation, total)
				return
			}
			if err != nil {
				if commitErr := p.Ledger.CommitPartial(reservation, total); commitErr != nil {
					yield(llm.StreamEvent{}, commitErr)
				}
				return
			}
		}
		if commitErr := p.Ledger.Commit(reservation, total); commitErr != nil {
			yield(llm.StreamEvent{}, commitErr)
		}
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
	req = requestWithReservation(req, reservation)
	msg, stop, usage, err := p.Provider.Complete(ctx, req)
	if err != nil {
		if commitErr := p.Ledger.CommitPartial(reservation, usage); commitErr != nil {
			return msg, stop, usage, fmt.Errorf("provider call failed: %v; usage accounting: %w", err, commitErr)
		}
		return msg, stop, usage, err
	}
	if err := p.Ledger.Commit(reservation, usage); err != nil {
		return msg, stop, usage, err
	}
	return msg, stop, usage, nil
}

func estimateRequestTokens(req llm.CompletionRequest) int {
	if raw, err := json.Marshal(req); err == nil {
		return (len(raw) + 2) / 3
	}
	// Best-effort fallback for values that cannot be JSON encoded. This still
	// counts every system segment, message content field, and advertised tool.
	n := 0
	for _, s := range req.System {
		n += len(s)
	}
	for _, m := range req.Messages {
		for _, b := range m.Content {
			n += len(b.Text) + len(b.Input) + len(b.Name)
		}
	}
	for _, tool := range req.Tools {
		n += len(tool.Name) + len(tool.Description)
		if raw, err := json.Marshal(tool.InputSchema); err == nil {
			n += len(raw)
		}
	}
	return (n + 2) / 3
}
