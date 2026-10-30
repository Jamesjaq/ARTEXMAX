package db

import "time"

type LLMProviderTelemetry struct {
	TaskID              string
	Worker              string
	Role                string
	Kind                string
	MemberID            int64
	ProfileName         string
	Model               string
	FallbackFrom        string
	FallbackTo          string
	LatencyMs           int
	InputTokens         int
	OutputTokens        int
	CacheRead           int
	CacheWrite          int
	EstimatedCostMicros int64
	BudgetDecision      string
	Status              string
	Error               string
	At                  time.Time
}

const llmProviderTelemetrySchema = `
CREATE TABLE IF NOT EXISTS llm_provider_telemetry (
 id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(),
 task_id TEXT, worker TEXT, role TEXT, kind TEXT NOT NULL,
 member_id BIGINT, profile_name TEXT, model TEXT,
 fallback_from TEXT, fallback_to TEXT, latency_ms INTEGER,
 input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
 cache_read INTEGER NOT NULL DEFAULT 0, cache_write INTEGER NOT NULL DEFAULT 0,
 estimated_cost_micros BIGINT NOT NULL DEFAULT 0, budget_decision TEXT,
 status TEXT, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_provider_telemetry_task ON llm_provider_telemetry(task_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_llm_provider_telemetry_profile ON llm_provider_telemetry(profile_name, ts DESC);
CREATE INDEX IF NOT EXISTS idx_llm_provider_telemetry_kind ON llm_provider_telemetry(kind, ts DESC);
`

func (d *DB) EnsureLLMProviderTelemetryTable() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(llmProviderTelemetrySchema); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) InsertLLMProviderTelemetry(t *LLMProviderTelemetry) error {
	_, err := d.Exec(`INSERT INTO llm_provider_telemetry
 (task_id,worker,role,kind,member_id,profile_name,model,fallback_from,fallback_to,latency_ms,input_tokens,output_tokens,cache_read,cache_write,estimated_cost_micros,budget_decision,status,error,ts)
 VALUES (NULLIF($1,''),NULLIF($2,''),NULLIF($3,''),$4,NULLIF($5,0),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),$10,$11,$12,$13,$14,$15,NULLIF($16,''),NULLIF($17,''),NULLIF($18,''),COALESCE(NULLIF($19::timestamptz,'0001-01-01 00:00:00+00'::timestamptz),now()))`,
		t.TaskID, t.Worker, t.Role, t.Kind, t.MemberID, t.ProfileName, t.Model, t.FallbackFrom, t.FallbackTo, t.LatencyMs, t.InputTokens, t.OutputTokens, t.CacheRead, t.CacheWrite, t.EstimatedCostMicros, t.BudgetDecision, t.Status, t.Error, t.At)
	return err
}
