package llmpool

import (
	"context"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

type telemetryContextKey struct{}

type TelemetryContext struct {
	TaskID string
	Worker string
	Role   string
}

func WithTelemetryContext(ctx context.Context, taskID, worker, role string) context.Context {
	return context.WithValue(ctx, telemetryContextKey{}, TelemetryContext{TaskID: strings.TrimSpace(taskID), Worker: strings.TrimSpace(worker), Role: strings.TrimSpace(role)})
}

func TelemetryContextFrom(ctx context.Context) TelemetryContext {
	if ctx == nil {
		return TelemetryContext{}
	}
	v, _ := ctx.Value(telemetryContextKey{}).(TelemetryContext)
	return v
}

type TelemetryEvent struct {
	Kind                string
	TaskID              string
	Worker              string
	Role                string
	MemberID            int64
	ProfileName         string
	Model               string
	FallbackFromProfile string
	FallbackToProfile   string
	LatencyMs           int
	Usage               llm.Usage
	EstimatedCostMicros int64
	BudgetDecision      string
	Status              string
	Error               string
}

type TelemetrySink func(TelemetryEvent)
