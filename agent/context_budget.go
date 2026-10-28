package agent

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// ContextItem is a candidate for the model-facing working set. The source ID
// lets a condenser and UI explain why an item was included without copying raw
// evidence into the prompt.
type ContextItem struct {
	ID        string
	Kind      string
	Text      string
	Tokens    int
	Priority  int
	Relevance int
	Recency   int
	Mandatory bool
	Trust     string
	Source    string
}

type ContextBudget struct {
	TotalTokens  int
	OutputTokens int
	SafetyTokens int
}

type ContextSelection struct {
	Items          []ContextItem
	UsedTokens     int
	Dropped        []ContextItem
	MandatoryOver  bool
	DroppedReasons map[string]string
}

// EstimateContextTokens intentionally uses a conservative, deterministic
// approximation. Provider-specific tokenizers can replace this later; the
// selection contract stays the same.
func EstimateContextTokens(s string) int {
	runes := utf8.RuneCountInString(s)
	if runes == 0 {
		return 0
	}
	// Four characters per token is a deliberately conservative cross-provider
	// estimate for mixed English, JSON, URLs, and non-ASCII evidence.
	return (runes + 3) / 4
}

// BuildContext selects mandatory policy/state first, then fills the remaining
// budget by active-intent relevance, priority, recency, and novelty. The full
// event/evidence log remains durable; this function only builds a projection.
func BuildContext(items []ContextItem, budget ContextBudget) ContextSelection {
	if budget.TotalTokens < 0 {
		budget.TotalTokens = 0
	}
	reserved := budget.OutputTokens + budget.SafetyTokens
	available := budget.TotalTokens - reserved
	if available < 0 {
		available = 0
	}
	for i := range items {
		if items[i].Tokens <= 0 {
			items[i].Tokens = EstimateContextTokens(items[i].Text)
		}
	}
	mandatory := make([]ContextItem, 0)
	optional := make([]ContextItem, 0)
	for _, item := range items {
		if item.Mandatory {
			mandatory = append(mandatory, item)
		} else {
			optional = append(optional, item)
		}
	}
	result := ContextSelection{DroppedReasons: map[string]string{}}
	for _, item := range mandatory {
		result.Items = append(result.Items, item)
		result.UsedTokens += item.Tokens
	}
	if result.UsedTokens > available {
		result.MandatoryOver = true
	}
	sort.SliceStable(optional, func(i, j int) bool {
		left := optional[i].Relevance*1000 + optional[i].Priority*100 + optional[i].Recency
		right := optional[j].Relevance*1000 + optional[j].Priority*100 + optional[j].Recency
		if left != right {
			return left > right
		}
		return optional[i].ID < optional[j].ID
	})
	for _, item := range optional {
		if item.ID == "" {
			item.ID = strings.Join([]string{item.Kind, item.Source}, ":")
		}
		if result.UsedTokens+item.Tokens <= available {
			result.Items = append(result.Items, item)
			result.UsedTokens += item.Tokens
			continue
		}
		result.Dropped = append(result.Dropped, item)
		result.DroppedReasons[item.ID] = "budget"
	}
	return result
}
