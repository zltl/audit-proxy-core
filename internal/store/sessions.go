package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const sessionColumns = `id, node_id, username, source_ip, client_version, target_id,
	target_host, target_port, upstream_login, status, started_at, last_seen_at, closed_at,
	bytes_in, bytes_out, recording_ref, revoke_requested, revoke_reason, termination_info,
	features, command_policy_id, record_policy, rule_id, max_session_seconds, idle_timeout_seconds`

// SessionFilter narrows a session listing.
type SessionFilter struct {
	Status   SessionStatus
	Username string
	NodeID   string
	TargetID string
	SourceIP string
	Limit    int
}

// CreateSession records a new proxied session.
func (s *Store) CreateSession(sess Session) (Session, error) {
	if sess.ID == "" {
		sess.ID = NewID("sess")
	}
	if sess.Status == "" {
		sess.Status = SessionActive
	}
	now := s.clock()
	if sess.StartedAt.IsZero() {
		sess.StartedAt = now
	}
	sess.LastSeenAt = now

	if sess.RecordPolicy == "" {
		sess.RecordPolicy = RecordFull
	}
	query := fmt.Sprintf(`INSERT INTO dp_sessions (%s) VALUES (%s)`, sessionColumns, s.binds(25))
	if _, err := s.db.Exec(query,
		sess.ID, sess.NodeID, sess.Username, sess.SourceIP, sess.ClientVersion, sess.TargetID,
		sess.TargetHost, sess.TargetPort, sess.UpstreamLogin, string(sess.Status),
		s.unix(sess.StartedAt), s.unix(sess.LastSeenAt), s.unix(sess.ClosedAt),
		sess.BytesIn, sess.BytesOut, sess.RecordingRef, sess.RevokeRequested,
		sess.RevokeReason, sess.TerminationInfo,
		int64(sess.Features), sess.CommandPolicyID, string(sess.RecordPolicy), sess.RuleID,
		int64(sess.MaxSessionTTL/time.Second), int64(sess.IdleTimeout/time.Second)); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// GetSession resolves a session by identifier.
func (s *Store) GetSession(id string) (Session, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_sessions WHERE id = %s LIMIT 1`, sessionColumns, s.bind(1))
	sess, err := scanSession(s.db.QueryRow(query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

// ListSessions returns sessions matching the filter, newest first.
func (s *Store) ListSessions(filter SessionFilter) ([]Session, error) {
	var (
		where []string
		args  []interface{}
	)
	add := func(clause string, value interface{}) {
		where = append(where, fmt.Sprintf(clause, s.bind(len(args)+1)))
		args = append(args, value)
	}
	if filter.Status != "" {
		add("status = %s", string(filter.Status))
	}
	if strings.TrimSpace(filter.Username) != "" {
		add("username = %s", strings.TrimSpace(filter.Username))
	}
	if strings.TrimSpace(filter.NodeID) != "" {
		add("node_id = %s", strings.TrimSpace(filter.NodeID))
	}
	if strings.TrimSpace(filter.TargetID) != "" {
		add("target_id = %s", strings.TrimSpace(filter.TargetID))
	}
	if strings.TrimSpace(filter.SourceIP) != "" {
		add("source_ip = %s", strings.TrimSpace(filter.SourceIP))
	}

	query := fmt.Sprintf(`SELECT %s FROM dp_sessions`, sessionColumns)
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY started_at DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := make([]Session, 0)
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

// CountActiveSessions counts a user's live sessions, optionally scoped to one
// target. This backs concurrency limits, so it counts in the database rather
// than in one node's memory.
func (s *Store) CountActiveSessions(username, targetID string) (int, error) {
	query := fmt.Sprintf(`SELECT COUNT(*) FROM dp_sessions WHERE status = %s AND username = %s`,
		s.bind(1), s.bind(2))
	args := []interface{}{string(SessionActive), strings.TrimSpace(username)}
	if strings.TrimSpace(targetID) != "" {
		query += fmt.Sprintf(` AND target_id = %s`, s.bind(3))
		args = append(args, strings.TrimSpace(targetID))
	}
	var count int
	if err := s.db.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// TouchSession refreshes the heartbeat and byte counters for a live session and
// reports whether an operator has asked for it to be cut off.
//
// Folding the revocation check into the heartbeat means a node learns about a
// kill request on its next update without a second query or a subscription,
// which keeps termination working even if the event stream is down.
func (s *Store) TouchSession(id string, bytesIn, bytesOut int64) (revoked bool, reason string, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, "", err
	}
	defer func() { _ = tx.Rollback() }()

	update := fmt.Sprintf(`UPDATE dp_sessions SET last_seen_at = %s, bytes_in = %s, bytes_out = %s
		WHERE id = %s AND status = %s`, s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5))
	result, err := tx.Exec(update, s.unix(s.clock()), bytesIn, bytesOut, id, string(SessionActive))
	if err != nil {
		return false, "", err
	}
	if affected, err := rowsAffected(result); err != nil {
		return false, "", err
	} else if affected == 0 {
		return false, "", ErrNotFound
	}

	query := fmt.Sprintf(`SELECT revoke_requested, revoke_reason FROM dp_sessions WHERE id = %s`, s.bind(1))
	if err := tx.QueryRow(query, id).Scan(&revoked, &reason); err != nil {
		return false, "", err
	}
	if err := tx.Commit(); err != nil {
		return false, "", err
	}
	return revoked, reason, nil
}

// CloseSession marks a session finished.
func (s *Store) CloseSession(id string, status SessionStatus, info string, bytesIn, bytesOut int64) error {
	if status == "" {
		status = SessionClosed
	}
	query := fmt.Sprintf(`UPDATE dp_sessions SET status = %s, closed_at = %s, last_seen_at = %s,
		bytes_in = %s, bytes_out = %s, termination_info = %s WHERE id = %s`,
		s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5), s.bind(6), s.bind(7))
	now := s.unix(s.clock())
	return requireAffected(s.db.Exec(query, string(status), now, now, bytesIn, bytesOut, info, id))
}

// SetRecordingRef attaches a recording location to a session.
func (s *Store) SetRecordingRef(id, ref string) error {
	query := fmt.Sprintf(`UPDATE dp_sessions SET recording_ref = %s WHERE id = %s`, s.bind(1), s.bind(2))
	return requireAffected(s.db.Exec(query, ref, id))
}

// RequestRevocation asks whichever node owns the session to disconnect it. The
// request is recorded rather than executed here because the node holding the
// socket is the only one that can actually close it.
func (s *Store) RequestRevocation(id, reason string) error {
	query := fmt.Sprintf(`UPDATE dp_sessions SET revoke_requested = %s, revoke_reason = %s
		WHERE id = %s AND status = %s`, s.bind(1), s.bind(2), s.bind(3), s.bind(4))
	return requireAffected(s.db.Exec(query, true, reason, id, string(SessionActive)))
}

// RevokeSessionsForUser marks every live session of a user for disconnection,
// which is what disabling an account or revoking a grant has to trigger.
func (s *Store) RevokeSessionsForUser(username, reason string) (int64, error) {
	query := fmt.Sprintf(`UPDATE dp_sessions SET revoke_requested = %s, revoke_reason = %s
		WHERE username = %s AND status = %s`, s.bind(1), s.bind(2), s.bind(3), s.bind(4))
	result, err := s.db.Exec(query, true, reason, strings.TrimSpace(username), string(SessionActive))
	if err != nil {
		return 0, err
	}
	return rowsAffected(result)
}

// ListRevokedSessions returns live sessions on a node that have been marked for
// disconnection.
func (s *Store) ListRevokedSessions(nodeID string) ([]Session, error) {
	query := fmt.Sprintf(`SELECT %s FROM dp_sessions
		WHERE revoke_requested = %s AND status = %s AND node_id = %s`,
		sessionColumns, s.bind(1), s.bind(2), s.bind(3))
	rows, err := s.db.Query(query, true, string(SessionActive), nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := make([]Session, 0)
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

// ReapStaleSessions closes sessions whose owning node stopped heartbeating, so
// that a crashed proxy does not leave rows that look active forever and hold
// concurrency slots against their users.
func (s *Store) ReapStaleSessions(olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, nil
	}
	cutoff := s.unix(s.clock().Add(-olderThan))
	query := fmt.Sprintf(`UPDATE dp_sessions SET status = %s, closed_at = %s,
		termination_info = %s WHERE status = %s AND last_seen_at > 0 AND last_seen_at < %s`,
		s.bind(1), s.bind(2), s.bind(3), s.bind(4), s.bind(5))
	result, err := s.db.Exec(query, string(SessionTerminated), s.unix(s.clock()),
		"node stopped heartbeating", string(SessionActive), cutoff)
	if err != nil {
		return 0, err
	}
	return rowsAffected(result)
}

// DeleteSessionsBefore prunes finished session rows older than a cutoff.
func (s *Store) DeleteSessionsBefore(cutoff time.Time) (int64, error) {
	query := fmt.Sprintf(`DELETE FROM dp_sessions WHERE status != %s AND closed_at > 0 AND closed_at < %s`,
		s.bind(1), s.bind(2))
	result, err := s.db.Exec(query, string(SessionActive), s.unix(cutoff))
	if err != nil {
		return 0, err
	}
	return rowsAffected(result)
}

func scanSession(row rowScanner) (Session, error) {
	var (
		sess                            Session
		status, recordPolicy            string
		startedAt, lastSeenAt, closedAt int64
		features                        int64
		maxSession, idleTimeout         int64
	)
	if err := row.Scan(&sess.ID, &sess.NodeID, &sess.Username, &sess.SourceIP, &sess.ClientVersion,
		&sess.TargetID, &sess.TargetHost, &sess.TargetPort, &sess.UpstreamLogin, &status,
		&startedAt, &lastSeenAt, &closedAt, &sess.BytesIn, &sess.BytesOut, &sess.RecordingRef,
		&sess.RevokeRequested, &sess.RevokeReason, &sess.TerminationInfo,
		&features, &sess.CommandPolicyID, &recordPolicy, &sess.RuleID,
		&maxSession, &idleTimeout); err != nil {
		return Session{}, err
	}
	sess.Status = SessionStatus(status)
	sess.StartedAt = fromUnix(startedAt)
	sess.LastSeenAt = fromUnix(lastSeenAt)
	sess.ClosedAt = fromUnix(closedAt)
	sess.Features = FeatureSet(features)
	sess.RecordPolicy = RecordPolicy(recordPolicy)
	sess.MaxSessionTTL = time.Duration(maxSession) * time.Second
	sess.IdleTimeout = time.Duration(idleTimeout) * time.Second
	return sess, nil
}
