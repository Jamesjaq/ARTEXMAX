# ARTEX control-plane implementation and end-to-end test plan

This document is the execution plan for turning the initial control-plane slice into the full ARTEX upgrade: durable runs, bounded context, deterministic policy, evidence-backed findings, safe execution, and operator-grade recovery.

## Current checkpoint

The repository now contains:

- `db/run_ledger.go`: append-only run events with parent IDs and idempotency keys, plus versioned run checkpoints.
- `db/schema.sql`: idempotent `run_events` and `run_checkpoints` tables and indexes.
- `agent/action_observation.go`: typed action and observation contracts with safety/bounds validation.
- `agent/context_budget.go`: deterministic context selection with mandatory items, output/safety reservations, ranking, and dropped-item reasons.
- Unit tests for the new contracts and context selection.

The current focused test command is:

```bash
export PATH=/usr/local/go/bin:$PATH
go test ./agent ./db ./intercept ./evidence ./llmpool
```

The complete suite additionally requires PostgreSQL because existing server integration tests open a configured ARTEX database.

## Latest implementation slice

Durable intent ownership is now wired into worker execution. `intent_leases`
stores the owner, expiry, heartbeat, and monotonic fencing token. Frontier and
detached chat claims acquire a lease; long worker runs heartbeat it; settlement
state changes use a token-checked compare-and-set; and cleanup/restart paths
release or reclaim expired leases. A stale worker therefore cannot complete or
reopen an intent after another worker has taken ownership. The remaining work
still includes wiring the deterministic action-policy evaluator into every
executor, provider cost accounting, signed check profiles, and restart/replay
fixture episodes. The evaluator itself now validates tool/capability allowlists,
target scope, action/byte/deadline budgets, and exact approval digests.
Signed passive profiles are implemented with version checks, HMAC verification,
GET/HEAD/OPTIONS-only enforcement, credential-header rejection, bounded body
and time limits, and authentication-aware request deduplication.
The runner executes these profiles with per-request timeouts, response-size
caps, redirect controls, normalized observations, truncation metadata, and
per-run request deduplication.

## End-to-end target architecture

The runtime should follow this invariant:

> The LLM proposes. The typed runtime validates. The policy gate authorizes. The executor acts. The event ledger records. The evidence store preserves. The evaluator verifies. The UI projects.

A run should progress through explicit states such as `created`, `planning`, `running`, `awaiting_approval`, `paused`, `cancelling`, `completed`, `failed`, and `reopened`. Every state transition should produce an immutable event. The current state is a projection, not an overwritten transcript.

Every externally visible effect must have:

- a stable run ID and action ID;
- an idempotency key;
- target scope and capability;
- policy decision and policy revision;
- timeout/deadline and cancellation path;
- structured observation;
- evidence references and hashes where applicable;
- a durable event before UI broadcast.

## Build order

### 1. Wire the ledger into planner and worker execution

Add a run/ledger dependency to the orchestration layer. Emit events at these boundaries:

1. run created;
2. planner proposes an intent;
3. worker claims an intent lease;
4. worker proposes an action;
5. policy evaluates the action;
6. approval is requested or automatically granted;
7. executor starts and completes;
8. observation/artifact is recorded;
9. finding is created or updated;
10. checkpoint is written;
11. worker releases/completes the intent;
12. run pauses, completes, fails, or is cancelled.

Use the existing task/exploration IDs as foreign or reference fields in event payloads during migration. Do not duplicate raw tool output into `run_events`; store it through `evidence/` and reference the artifact.

Acceptance criteria:

- Restarting the server does not lose a run’s latest checkpoint.
- Replaying an event stream reconstructs the same projected state.
- Repeating an event with the same idempotency key does not create a duplicate.
- A stale worker cannot overwrite a newer checkpoint or complete an intent it no longer owns.

### 2. Add leases, heartbeats, fencing, and cancellation

Create durable lease records or event-backed lease transitions for intent claims and worker execution. A lease must have an owner, expiry, heartbeat time, and fencing token. Every write from a worker must include the fencing token and fail if ownership is stale.

Test:

- two workers racing for one intent;
- heartbeat loss and lease expiry;
- a stale worker finishing after another worker acquired the lease;
- cancellation during a model call;
- cancellation during a subprocess/tool call;
- server restart during each state;
- repeated release and repeated cancellation.

### 3. Make the bounded context builder the only model input path

Build the model request from a projection containing:

1. immutable scope and authorization;
2. tool schemas/capabilities for the current role;
3. current phase, intent, checkpoint, approvals, and deadline;
4. recent head/tail events;
5. relevant facts and evidence summaries;
6. versioned condensation summary;
7. output reservation and safety margin.

Raw transcripts and raw tool output remain durable but are never automatically injected wholesale.

Add token accounting to every model call: estimated input, actual input where available, output, reserved safety, selected item IDs, dropped item IDs, condenser version, and retrieval query. Add a debug endpoint/UI showing why each context item was selected.

Test:

- deterministic selection under ties;
- policy and scope are never dropped;
- output/safety reservation is honored;
- oversized tool output becomes an artifact reference plus bounded observation;
- condensation preserves source IDs and raw evidence remains retrievable;
- retrieved text cannot mutate scope or approval state;
- adversarial evidence text is displayed as untrusted data.

### 4. Add the policy and approval gate

Place the gate after action validation and before execution. It should enforce:

- tenant and user authorization;
- target scope and allow/deny rules;
- tool/capability allowlists;
- read-only versus destructive classification;
- host, rate, byte, time, and concurrency budgets;
- required human approval;
- expiry and cancellation;
- secret and sensitive-data rules.

Bind an approval to the exact action digest, run, checkpoint, policy revision, reviewer, expiry, and decision. Any changed argument requires a new approval.

Test:

- out-of-scope target rejection;
- modified action after approval;
- expired approval;
- replayed approval from another run;
- missing reviewer authorization;
- quota exhaustion;
- fail-closed behavior when policy storage is unavailable;
- redaction before persistence and UI streaming.

### 5. Normalize executors and evidence

Adapt existing tools behind the typed action/observation boundary. Every executor should return status, timing, exit/error information, byte counts, truncation, redaction state, artifact references, and provenance.

Keep full traffic, screenshots, command output, and files in evidence storage. The event ledger and model context contain compact metadata and immutable artifact IDs.

Add content hashes, evidence access controls, retention policy, and raw-evidence opt-in. Never expose secrets through generic logs, notifications, or model prompts by default.

Test:

- body/output size caps;
- UTF-8-safe truncation;
- artifact hash mismatch;
- redaction of tokens, cookies, authorization headers, and private data;
- evidence access across tenants;
- evidence retention and deletion behavior;
- export/import preserving provenance.

### 6. Add deterministic checks and normalized HTTP observations

Introduce a small, signed/versioned check-profile format for low-impact HTTP checks. Start with passive checks and explicitly bounded requests. Add canonical request deduplication, finding deduplication, host-health circuit breakers, rate limits, response caps, redirect controls, and safe retry classification.

LLMs may propose a profile, but only validated, policy-approved profiles execute. Do not enable unrestricted fuzzing, arbitrary code, OOB, JavaScript, or headless execution by default.

Test with authorized fixture targets only:

- same request is deduplicated;
- different credentials/session context is not incorrectly deduplicated;
- retry only occurs for permitted methods/errors;
- host circuit breaker opens and recovers;
- rate limits are enforced across concurrent workers;
- normalized observations preserve redirect/provenance/truncation metadata;
- findings are stable across repeated runs.

### 7. Add provider routing and cost controls

Extend `llmpool` with role-based model groups: reasoner, summarizer, extractor/classifier, verifier. Add capability/context-window filtering, bounded retries, explicit fallback groups, cooldowns, per-run and tenant budgets, and provider telemetry.

Record requested model group, served provider/model, attempt chain, latency, tokens, estimated cost, fallback reason, cache status, and policy decision. Do not use semantic caching for state-changing or context-sensitive security decisions by default.

Test:

- provider timeout and retry;
- quota/circuit-breaker transition;
- context-window routing;
- disallowed region/provider rejection;
- fallback changing model is visible in the event ledger;
- duplicate stateful requests are prevented;
- budget enforcement works across multiple workers.

### 8. Add findings provenance and baseline lifecycle

Define stable finding identity from check/rule ID, asset/request location, normalized evidence fingerprint, and relevant engine/version—not from LLM prose. Track `introduced`, `persistent`, `changed`, `resolved`, `dismissed`, and `needs_verification` states.

Represent provenance paths with bounded source, transformation, validation/sanitization, and observed-outcome edges. Require evidence and confidence before a finding becomes report-ready.

Test:

- same finding remains stable when presentation text changes;
- new run creates an introduced finding;
- missing finding becomes resolved only after the configured verification policy;
- evidence links remain valid after compaction;
- unsupported LLM claims cannot be promoted without evidence.

### 9. Add a deterministic episode harness

Create authorized fixture scenarios with pinned target snapshots, tool/profile versions, policy revisions, model configuration, seeds, and budgets. Persist every action, observation, policy decision, approval, artifact, token count, latency, and result.

Required metrics:

- tokens per useful observation;
- repeated-action rate;
- time to first useful finding;
- evidence completeness;
- unsupported-claim rate;
- approval correctness;
- scope violations;
- cancellation latency;
- restart recovery rate;
- provider cost and fallback rate;
- finding precision/recall on fixtures.

Every architecture change should be compared against a baseline episode set before being considered an improvement.

## Required test layers

### Fast unit tests

Run on every change:

```bash
export PATH=/usr/local/go/bin:$PATH
go test ./agent ./db ./intercept ./evidence ./llmpool ./guard ./traffic
```

These cover validation, budgeting, graph logic, policy parsing, evidence integrity, and provider state machines.

### Database integration tests

Run with PostgreSQL 16 or the project-supported version:

```bash
export ARTEX_PG_DSN='postgres://artex:password@127.0.0.1:5433/artex?sslmode=disable'
export PATH=/usr/local/go/bin:$PATH
go test ./db ./server
```

The database test harness must verify schema idempotence by opening the same database twice and must exercise event idempotency, checkpoint recovery, lease fencing, migrations, and archive compatibility.

### End-to-end control-plane tests

Run against an isolated authorized fixture environment with mock or deterministic model providers:

1. create a run;
2. create a scope and policy;
3. start planner;
4. create/claim an intent;
5. propose an action;
6. deny one action and verify no executor call occurs;
7. approve one exact action;
8. execute it and persist observation/evidence;
9. force context compaction;
10. kill and restart the service;
11. resume from the latest checkpoint;
12. complete a finding;
13. reopen it with external feedback;
14. export the event/evidence package;
15. verify hashes and provenance.

Assertions must inspect both API-visible behavior and the durable event/evidence records.

### Security and resilience tests

Run separately from ordinary unit tests:

- prompt/evidence injection attempts;
- cross-tenant event/checkpoint access;
- stale approval replay;
- stale lease writes;
- secret leakage through context, logs, notifications, and exports;
- policy-store outage;
- provider outage and fallback;
- event broadcast duplication/reordering/reconnect;
- oversized output and archive bomb limits;
- subprocess timeout and kill behavior;
- network egress enforcement;
- database restart and transaction retry.

## Definition of done for the full upgrade

The upgrade is complete only when:

- every run is restartable from durable checkpoints;
- every external effect is policy-evaluated and idempotently recorded;
- no model prompt requires the full transcript;
- summaries and retrieval cite durable source IDs;
- raw evidence is preserved independently of context compaction;
- findings have stable identity, provenance, and lifecycle state;
- provider fallbacks and costs are visible;
- the UI can reconnect and replay from event IDs;
- authorized end-to-end fixtures pass deterministically;
- security tests show no cross-scope approval, evidence, or checkpoint leakage;
- PostgreSQL migrations are idempotent and backwards-compatible;
- the full CI suite passes with no hidden dependency on a developer workstation.
