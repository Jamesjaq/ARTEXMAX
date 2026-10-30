package agent

import (
	"context"
	"errors"
	"time"
)

// EpisodeEvent is the bounded, deterministic record used by fixture episodes.
// It intentionally stores digests and compact observations, never raw bodies.
type EpisodeEvent struct {
	Kind         string
	ActionID     string
	ActionDigest string
	Status       string
	Reason       string
}

type EpisodeResult struct {
	Status       string
	Events       []EpisodeEvent
	Observations []Observation
	Usage        PolicyUsage
}

// RunPassiveEpisode executes a signed passive profile through the same policy
// boundary used by production orchestration. It is deterministic for a fixed
// HTTP fixture, profile, policy, and initial usage, making it suitable for
// replay and regression tests.
func RunPassiveEpisode(ctx context.Context, runner *PassiveRunner, profile PassiveProfile, secret []byte, authContext string, policy Policy, usage PolicyUsage, approval *Approval, now time.Time) (EpisodeResult, error) {
	if runner == nil {
		return EpisodeResult{}, errors.New("passive runner is required")
	}
	result, err := runner.RunAuthorized(ctx, profile, secret, authContext, policy, usage, approval, now)
	if err != nil {
		return EpisodeResult{}, err
	}
	episode := EpisodeResult{Status: "completed", Observations: result.Observations, Usage: result.Usage}
	for i, decision := range result.Decisions {
		kind := "policy_evaluated"
		status := "denied"
		if decision.Allowed {
			status = "allowed"
		}
		actionID := ""
		if i < len(profile.Checks) {
			actionID = profile.Checks[i].ID
		}
		episode.Events = append(episode.Events, EpisodeEvent{Kind: kind, ActionID: actionID, ActionDigest: decision.ActionDigest, Status: status, Reason: decision.Reason})
	}
	for _, observation := range result.Observations {
		episode.Events = append(episode.Events, EpisodeEvent{Kind: "observation_recorded", ActionID: observation.ActionID, Status: observation.Status, Reason: observation.ErrorCode})
	}
	episode.Events = append(episode.Events, EpisodeEvent{Kind: "run_status_changed", Status: episode.Status})
	return episode, nil
}
