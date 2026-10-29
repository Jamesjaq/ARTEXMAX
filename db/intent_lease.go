package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrIntentLeaseUnavailable means another live worker owns the intent.
	ErrIntentLeaseUnavailable = errors.New("intent lease is held by another worker")
	// ErrIntentLeaseStale means the caller's owner/token no longer fences writes.
	ErrIntentLeaseStale = errors.New("intent lease is stale")
)

const defaultIntentLeaseTTL = 45 * time.Second

// IntentLease is the durable execution ownership record for one intent.
// FencingToken is monotonic for the lifetime of the intent and must accompany
// every worker-owned mutation.
type IntentLease struct {
	IntentID      int64
	ExplorationID int64
	Owner         string
	FencingToken  int64
	HeartbeatAt   time.Time
	ExpiresAt     time.Time
}

// ClaimIntentLease atomically claims an open intent, or takes over an expired
// lease. A transaction row-locks the graph node before inspecting the lease, so
// two workers cannot both believe they own the same intent.
func (s *ExplorationStore) ClaimIntentLease(id int64, owner string, ttl time.Duration) (IntentLease, bool, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return IntentLease{}, false, fmt.Errorf("owner is required")
	}
	if ttl <= 0 {
		ttl = defaultIntentLeaseTTL
	}
	tx, err := s.db.Begin()
	if err != nil {
		return IntentLease{}, false, err
	}
	defer tx.Rollback()

	var state string
	if err := tx.QueryRow(`SELECT state FROM exploration_nodes
		WHERE id=$1 AND exploration_id=$2 AND kind='intent' FOR UPDATE`, id, s.expID).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IntentLease{}, false, nil
		}
		return IntentLease{}, false, err
	}
	var current IntentLease
	var expires time.Time
	err = tx.QueryRow(`SELECT owner, fencing_token, heartbeat_at, expires_at
		FROM intent_leases WHERE intent_id=$1 FOR UPDATE`, id).
		Scan(&current.Owner, &current.FencingToken, &current.HeartbeatAt, &expires)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return IntentLease{}, false, err
	}
	now := time.Now().UTC()
	if err == nil && expires.After(now) && current.Owner != owner {
		return IntentLease{}, false, nil
	}
	if state != "open" && state != "running" {
		return IntentLease{}, false, nil
	}

	token := int64(1)
	if err == nil {
		token = current.FencingToken + 1
	}
	lease := IntentLease{IntentID: id, ExplorationID: s.expID, Owner: owner, FencingToken: token, HeartbeatAt: now, ExpiresAt: now.Add(ttl)}
	if _, err := tx.Exec(`UPDATE exploration_nodes SET state='running', owner=$1
		WHERE id=$2 AND exploration_id=$3 AND kind='intent'`, owner, id, s.expID); err != nil {
		return IntentLease{}, false, err
	}
	if err == sql.ErrNoRows {
		_, err = tx.Exec(`INSERT INTO intent_leases(intent_id, exploration_id, owner, fencing_token, heartbeat_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6)`, id, s.expID, owner, token, now, lease.ExpiresAt)
	} else {
		_, err = tx.Exec(`UPDATE intent_leases SET owner=$1, fencing_token=$2, heartbeat_at=$3, expires_at=$4
			WHERE intent_id=$5 AND exploration_id=$6`, owner, token, now, lease.ExpiresAt, id, s.expID)
	}
	if err != nil {
		return IntentLease{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return IntentLease{}, false, err
	}
	return lease, true, nil
}

// HeartbeatIntentLease extends a lease only when both owner and fencing token
// match. An expired lease cannot be revived by a stale worker.
func (s *ExplorationStore) HeartbeatIntentLease(id int64, owner string, token int64, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		ttl = defaultIntentLeaseTTL
	}
	now := time.Now().UTC()
	res, err := s.db.Exec(`UPDATE intent_leases
		SET heartbeat_at=$1, expires_at=$2
		WHERE intent_id=$3 AND exploration_id=$4 AND owner=$5 AND fencing_token=$6 AND expires_at>$1`,
		now, now.Add(ttl), id, s.expID, owner, token)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// FencedCompareAndSetIntentState is the only safe terminal transition for a
// leased worker. It refuses writes from an expired or superseded owner.
func (s *ExplorationStore) FencedCompareAndSetIntentState(id int64, expected, state, owner string, token int64) (bool, error) {
	terminal := state == "done" || state == "blocked" || state == "exhausted" || state == "stopped"
	res, err := s.db.Exec(`UPDATE exploration_nodes n SET state=$1, blocked_reason=NULL,
		content_version=content_version+1, completed_at=CASE WHEN $7 THEN now() ELSE NULL END
		FROM intent_leases l
		WHERE n.id=$2 AND n.exploration_id=$3 AND n.kind='intent' AND n.state=$4
		  AND l.intent_id=n.id AND l.exploration_id=n.exploration_id
		  AND l.owner=$5 AND l.fencing_token=$6 AND l.expires_at>now()`,
		state, id, s.expID, expected, owner, token, terminal)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, ErrIntentLeaseStale
	}
	return true, nil
}

// ReleaseIntentLease removes ownership only for the current owner/token.
func (s *ExplorationStore) ReleaseIntentLease(id int64, owner string, token int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM intent_leases
		WHERE intent_id=$1 AND exploration_id=$2 AND owner=$3 AND fencing_token=$4`, id, s.expID, owner, token)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ReclaimExpiredIntentLeases returns abandoned running intents to the frontier
// and removes only expired lease rows. It is safe to call during startup and on
// a periodic recovery tick.
func (s *ExplorationStore) ReclaimExpiredIntentLeases() (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE exploration_nodes n SET state='open', owner=NULL
		WHERE n.exploration_id=$1 AND n.kind='intent' AND n.state='running'
		  AND EXISTS (SELECT 1 FROM intent_leases l WHERE l.intent_id=n.id AND l.expires_at<=now())`, s.expID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.Exec(`DELETE FROM intent_leases WHERE exploration_id=$1 AND expires_at<=now()`, s.expID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}
