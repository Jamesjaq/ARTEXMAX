package lab

import (
	"context"
	"testing"
)

func TestRunDeterministicFixtureBeatsBaselines(t *testing.T) {
	first, err := Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Winner != "artex-policy" {
		t.Fatalf("winner=%q results=%+v", first.Winner, first.Results)
	}
	if len(first.Beats) != 2 || !contains(first.Beats, "naive-unbounded") || !contains(first.Beats, "deny-all") {
		t.Fatalf("beats=%v", first.Beats)
	}
	if first.Results[0].Score != second.Results[0].Score || first.Results[0].Requests != 1 {
		t.Fatalf("non-deterministic reports: first=%+v second=%+v", first, second)
	}
	naive := find(first.Results, "naive-unbounded")
	denyAll := find(first.Results, "deny-all")
	if naive.PolicyViolations != 1 || denyAll.UsefulObservations != 0 {
		t.Fatalf("unexpected baseline metrics: %+v", first.Results)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func find(results []Result, strategy string) Result {
	for _, result := range results {
		if result.Strategy == strategy {
			return result
		}
	}
	return Result{}
}
