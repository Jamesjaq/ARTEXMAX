package llmpool

import (
	"context"
	"errors"
	"iter"
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
	ledger := NewUsageLedger(Budget{MaxInputTokens: 20, MaxOutputTokens: 10, MaxTotalTokens: 30, MaxCostMicros: 5000, InputMicrosPerK: 1000, OutputMicrosPerK: 2000})
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
	_, _, _, err = p.Complete(context.Background(), llm.CompletionRequest{MaxTokens: 10})
	if !errors.Is(err, errors.New("LLM input-token budget exhausted")) && err == nil {
		t.Fatal("second call unexpectedly passed budget")
	}
}
