# ARTEX evaluation lab

The lab is a deterministic, offline fixture harness for comparing the real ARTEX passive-policy path with explicit strategy baselines. It does not contact external targets or claim to benchmark named commercial products.

Run it with:

```bash
export PATH=/usr/local/go/bin:$PATH
go test ./lab ./cmd/artex-lab
go run ./cmd/artex-lab
# or archive JSON:
go run ./cmd/artex-lab -out /tmp/artex-lab.json
```

The fixture contains two read-only HTTP checks and a one-action policy budget. The strategies are:

- `artex-policy`: runs the signed profile through `RunPassiveEpisode`, policy evaluation, scope validation, body limits, and bounded execution.
- `naive-unbounded`: represents raw collection without the policy boundary. It collects both checks and is penalized for exceeding the action budget.
- `deny-all`: represents a safety-maximizing strategy that performs no work.

The score intentionally weights safety violations more heavily than collection volume. On the current fixture, ARTEX produces one useful observation, denies the over-budget action, makes one request, and scores above both baselines. This is evidence that the policy boundary wins on this scenario—not evidence that ARTEX beats external scanners or agents. Add named adapters, pinned fixtures, and a broader scenario matrix before making a competitive claim.
