package llmpool

import (
	"context"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

type budgetProvider struct{ usage llm.Usage }

func (p budgetProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{Usage: p.usage}, nil)
	}
}
func (p budgetProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "stop", p.usage, nil
}

type streamingBudgetProvider struct{ chunks []llm.Usage }

func (p streamingBudgetProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		for _, usage := range p.chunks {
			if !yield(llm.StreamEvent{Usage: usage}, nil) {
				return
			}
		}
	}
}
func (p streamingBudgetProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "stop", llm.Usage{}, nil
}

type requestRecorderProvider struct {
	requests []llm.CompletionRequest
	usages   []llm.Usage
}

func (p *requestRecorderProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {}
}
func (p *requestRecorderProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	index := len(p.requests) - 1
	if index >= len(p.usages) {
		return llm.Message{}, "stop", llm.Usage{}, nil
	}
	return llm.Message{}, "stop", p.usages[index], nil
}

func TestRouteRequiresExplicitRole(t *testing.T) {
	p := budgetProvider{}
	r := Route{Groups: map[Role]llm.Provider{RoleVerifier: p}}
	if got, err := r.Provider(RoleVerifier); err != nil || got == nil {
		t.Fatalf("verifier route: %v", err)
	}
	if _, err := r.Provider(RoleReasoner); err == nil {
		t.Fatal("missing role route was allowed")
	}
}

func TestBudgetedProviderEnforcesAndRecordsCost(t *testing.T) {
	ledger := NewUsageLedger(Budget{MaxInputTokens: 10, MaxOutputTokens: 10, MaxTotalTokens: 30, MaxCostMicros: 5000, InputMicrosPerK: 1000, OutputMicrosPerK: 2000})
	p := BudgetedProvider{Provider: budgetProvider{usage: llm.Usage{InputTokens: 5, OutputTokens: 4}}, Ledger: ledger, EstimateInput: func(llm.CompletionRequest) int { return 5 }}
	_, _, usage, err := p.Complete(context.Background(), llm.CompletionRequest{MaxTokens: 10})
	if err != nil {
		t.Fatal(err)
	}
	if usage.InputTokens != 5 || usage.OutputTokens != 4 {
		t.Fatalf("usage=%+v", usage)
	}
	got, cost := ledger.Snapshot()
	if got != usage || cost != 13 {
		t.Fatalf("snapshot=%+v cost=%d", got, cost)
	}
	p.EstimateInput = func(llm.CompletionRequest) int { return 6 }
	_, _, _, err = p.Complete(context.Background(), llm.CompletionRequest{MaxTokens: 1})
	if err == nil || !strings.Contains(err.Error(), "LLM input-token budget exhausted") {
		t.Fatalf("expected input-token budget denial, got %v", err)
	}
}

func TestBudgetedProviderCapsUncappedCallsAndStopsAtCumulativeOutputLimit(t *testing.T) {
	provider := &requestRecorderProvider{usages: []llm.Usage{{OutputTokens: 3}, {OutputTokens: 2}}}
	ledger := NewUsageLedger(Budget{MaxOutputTokens: 5, MaxOutputPerCallTokens: 4})
	p := BudgetedProvider{Provider: provider, Ledger: ledger}
	for range 2 {
		if _, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(provider.requests) != 2 || provider.requests[0].MaxTokens != 4 || provider.requests[1].MaxTokens != 2 {
		t.Fatalf("provider requests did not receive the reserved output caps: %+v", provider.requests)
	}
	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
	if err == nil || !strings.Contains(err.Error(), "output-token budget exhausted") {
		t.Fatalf("expected cumulative output denial, got %v", err)
	}
	if len(provider.requests) != 2 {
		t.Fatalf("provider was called after the output budget was exhausted: %d calls", len(provider.requests))
	}
}

func TestBudgetedProviderRejectsUncappedHardBudget(t *testing.T) {
	provider := &requestRecorderProvider{}
	p := BudgetedProvider{Provider: provider, Ledger: NewUsageLedger(Budget{MaxOutputTokens: 10})}
	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
	if err == nil || !strings.Contains(err.Error(), "uncapped request") {
		t.Fatalf("expected uncapped request to fail closed, got %v", err)
	}
	if len(provider.requests) != 0 {
		t.Fatal("provider was called despite the missing output cap")
	}
}

func TestBudgetedProviderRecordsActualTokenOverruns(t *testing.T) {
	cases := []struct {
		name   string
		budget Budget
		usage  llm.Usage
		want   string
	}{
		{"input", Budget{MaxInputTokens: 4}, llm.Usage{InputTokens: 5}, "input-token budget exceeded"},
		{"output", Budget{MaxOutputTokens: 4, MaxOutputPerCallTokens: 2}, llm.Usage{OutputTokens: 5}, "output-token budget exceeded"},
		{"total", Budget{MaxTotalTokens: 4}, llm.Usage{InputTokens: 3, OutputTokens: 2}, "total-token budget exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := BudgetedProvider{Provider: budgetProvider{usage: tc.usage}, Ledger: NewUsageLedger(tc.budget), EstimateInput: func(llm.CompletionRequest) int { return 2 }}
			_, _, returnedUsage, err := p.Complete(context.Background(), llm.CompletionRequest{MaxTokens: 2})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected actual %s overrun, got %v", tc.name, err)
			}
			storedUsage, _ := p.Ledger.Snapshot()
			if returnedUsage != tc.usage || storedUsage != tc.usage {
				t.Fatalf("overrun usage was not preserved: returned=%+v stored=%+v want=%+v", returnedUsage, storedUsage, tc.usage)
			}
		})
	}
}

func TestBudgetedProviderAggregatesStreamingUsage(t *testing.T) {
	ledger := NewUsageLedger(Budget{})
	p := BudgetedProvider{Provider: streamingBudgetProvider{chunks: []llm.Usage{{InputTokens: 2}, {OutputTokens: 3, CacheReadTokens: 1}}}, Ledger: ledger, EstimateInput: func(llm.CompletionRequest) int { return 4 }}
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{MaxTokens: 10}) {
		if err != nil {
			t.Fatal(err)
		}
	}
	usage, _ := ledger.Snapshot()
	want := llm.Usage{InputTokens: 2, OutputTokens: 3, CacheReadTokens: 1}
	if usage != want {
		t.Fatalf("stream usage=%+v want=%+v", usage, want)
	}
}

func TestBudgetedProviderRecordsActualCostOverrun(t *testing.T) {
	ledger := NewUsageLedger(Budget{MaxCostMicros: 5, InputMicrosPerK: 1000, OutputMicrosPerK: 1000})
	p := BudgetedProvider{Provider: budgetProvider{usage: llm.Usage{InputTokens: 5000, OutputTokens: 5000}}, Ledger: ledger, EstimateInput: func(llm.CompletionRequest) int { return 1 }}
	_, _, usage, err := p.Complete(context.Background(), llm.CompletionRequest{MaxTokens: 1})
	if err == nil || !strings.Contains(err.Error(), "cost budget exceeded by actual provider usage") {
		t.Fatalf("unexpected cost overrun error: %v", err)
	}
	stored, cost := ledger.Snapshot()
	if usage.InputTokens != 5000 || usage.OutputTokens != 5000 || stored != usage || cost != 10000 {
		t.Fatalf("actual over-budget usage was lost: returned=%+v stored=%+v cost=%d", usage, stored, cost)
	}
}

func TestBudgetedProviderCostReservationRequiresPrices(t *testing.T) {
	ledger := NewUsageLedger(Budget{MaxCostMicros: 100})
	p := BudgetedProvider{Provider: budgetProvider{}, Ledger: ledger, EstimateInput: func(llm.CompletionRequest) int { return 1 }}
	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{MaxTokens: 1})
	if err == nil || !strings.Contains(err.Error(), "no usable pricing rates") {
		t.Fatalf("cost budget accepted missing prices: %v", err)
	}
}
