package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	FindingLifecycleIntroduced        = "introduced"
	FindingLifecyclePersistent        = "persistent"
	FindingLifecycleChanged           = "changed"
	FindingLifecycleResolved          = "resolved"
	FindingLifecycleDismissed         = "dismissed"
	FindingLifecycleNeedsVerification = "needs_verification"
)

func validFindingLifecycle(s string) bool {
	switch s {
	case FindingLifecycleIntroduced, FindingLifecyclePersistent, FindingLifecycleChanged,
		FindingLifecycleResolved, FindingLifecycleDismissed, FindingLifecycleNeedsVerification:
		return true
	default:
		return false
	}
}

// FindingIdentity returns a stable, presentation-independent identity. Asset
// IDs are sorted and evidence is reduced to a whitespace-normalized fingerprint;
// summaries, titles, and worker names deliberately do not participate.
func FindingIdentity(ruleID, engineVersion, location, evidence string, assetIDs []int64) string {
	ids := append([]int64(nil), assetIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	canonical := struct {
		Rule     string  `json:"rule"`
		Engine   string  `json:"engine"`
		Location string  `json:"location"`
		Evidence string  `json:"evidence"`
		Assets   []int64 `json:"assets"`
	}{
		Rule:     strings.ToLower(strings.TrimSpace(ruleID)),
		Engine:   strings.TrimSpace(engineVersion),
		Location: strings.ToLower(strings.TrimSpace(location)),
		Evidence: normalizeFindingEvidence(evidence),
		Assets:   ids,
	}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func normalizeFindingEvidence(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

// SetFindingLifecycle changes the machine lifecycle only when the requested
// state is valid. Verification states also update the verification timestamp
// and count, making repeated retests auditable without altering triage status.
func (d *DB) SetFindingLifecycle(id int64, state string, verifiedAt time.Time) error {
	if id <= 0 {
		return errors.New("finding id is required")
	}
	if !validFindingLifecycle(state) {
		return fmt.Errorf("invalid finding lifecycle %q", state)
	}
	if verifiedAt.IsZero() {
		verifiedAt = time.Now().UTC()
	}
	_, err := d.Exec(`UPDATE findings SET lifecycle_state=$1,
		last_verified_at=CASE WHEN $2 THEN $3 ELSE last_verified_at END,
		verification_runs=CASE WHEN $2 THEN verification_runs+1 ELSE verification_runs END
		WHERE id=$4`, state, state == FindingLifecyclePersistent || state == FindingLifecycleChanged || state == FindingLifecycleResolved, verifiedAt, id)
	return err
}

// MarkFindingRunMissing marks a previously observed identity as requiring
// verification rather than immediately declaring it resolved. Resolution is a
// policy decision that should follow an explicit retest.
func (d *DB) MarkFindingRunMissing(identity string) error {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return errors.New("finding identity is required")
	}
	_, err := d.Exec(`UPDATE findings SET lifecycle_state=$1
		WHERE identity_key=$2 AND lifecycle_state NOT IN ($3,$4)`,
		FindingLifecycleNeedsVerification, identity, FindingLifecycleResolved, FindingLifecycleDismissed)
	return err
}
