package agent

import "testing"

func TestBuildContextReservesOutputAndSafetyBudget(t *testing.T) {
	got := BuildContext([]ContextItem{
		{ID: "scope", Kind: "policy", Text: "scope", Mandatory: true},
		{ID: "relevant", Text: "relevant", Relevance: 10},
		{ID: "stale", Text: "stale", Relevance: 1},
	}, ContextBudget{TotalTokens: 10, OutputTokens: 3, SafetyTokens: 2})
	if got.UsedTokens > 7 {
		t.Fatalf("context exceeded reserved budget: used=%d", got.UsedTokens)
	}
	if len(got.Items) != 2 || got.Items[0].ID != "scope" || got.Items[1].ID != "relevant" {
		t.Fatalf("unexpected selection: %+v", got.Items)
	}
	if len(got.Dropped) != 1 || got.Dropped[0].ID != "stale" {
		t.Fatalf("unexpected dropped items: %+v", got.Dropped)
	}
}

func TestBuildContextMandatoryItemsAreNeverDropped(t *testing.T) {
	got := BuildContext([]ContextItem{
		{ID: "scope", Text: "this is larger than the available budget", Mandatory: true},
	}, ContextBudget{TotalTokens: 2, OutputTokens: 1, SafetyTokens: 1})
	if len(got.Items) != 1 || !got.MandatoryOver {
		t.Fatalf("mandatory item must be retained and flagged: %+v", got)
	}
}

func TestBuildContextIsDeterministicOnTies(t *testing.T) {
	got := BuildContext([]ContextItem{
		{ID: "b", Text: "bbbb", Relevance: 1},
		{ID: "a", Text: "aaaa", Relevance: 1},
	}, ContextBudget{TotalTokens: 1})
	if len(got.Items) != 1 || got.Items[0].ID != "a" {
		t.Fatalf("tie should resolve by stable id: %+v", got.Items)
	}
}

func TestEstimateContextTokensHandlesUTF8(t *testing.T) {
	if got := EstimateContextTokens("€€€€"); got != 1 {
		t.Fatalf("UTF-8 token estimate=%d, want 1", got)
	}
	if got := EstimateContextTokens(""); got != 0 {
		t.Fatalf("empty token estimate=%d, want 0", got)
	}
}
