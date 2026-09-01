package store

import (
	"errors"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })

	created, err := s.CreateSession(Session{
		NodeID:        "node-a",
		Username:      "alice",
		SourceIP:      "10.0.0.5",
		ClientVersion: "SSH-2.0-OpenSSH_9.6",
		TargetID:      "tgt-1",
		TargetHost:    "10.0.1.10",
		TargetPort:    22,
		UpstreamLogin: "deploy",
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if created.ID == "" || created.Status != SessionActive {
		t.Fatalf("defaults not applied: %+v", created)
	}

	fetched, err := s.GetSession(created.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if fetched.UpstreamLogin != "deploy" || fetched.ClientVersion != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("round-trip lost fields: %+v", fetched)
	}

	revoked, _, err := s.TouchSession(created.ID, 1024, 4096)
	if err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	if revoked {
		t.Fatal("a healthy session should not report a revocation")
	}
	fetched, _ = s.GetSession(created.ID)
	if fetched.BytesIn != 1024 || fetched.BytesOut != 4096 {
		t.Fatalf("byte counters not updated: %+v", fetched)
	}

	if err := s.SetRecordingRef(created.ID, "s3://bucket/sess.cast"); err != nil {
		t.Fatalf("SetRecordingRef: %v", err)
	}

	if err := s.CloseSession(created.ID, SessionClosed, "client disconnected", 2048, 8192); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	closed, _ := s.GetSession(created.ID)
	if closed.Status != SessionClosed || closed.ClosedAt.IsZero() {
		t.Fatalf("close not recorded: %+v", closed)
	}
	if closed.RecordingRef != "s3://bucket/sess.cast" {
		t.Fatalf("recording reference lost: %+v", closed)
	}
	if closed.Duration(now) != 0 {
		t.Fatalf("a session opened and closed at the same instant should have zero duration, got %v",
			closed.Duration(now))
	}

	// Touching a closed session must not resurrect it.
	if _, _, err := s.TouchSession(created.ID, 1, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("touching a closed session should fail, got %v", err)
	}
}

func TestRevocationIsVisibleToTheOwningNode(t *testing.T) {
	s := newTestStore(t)

	sess, err := s.CreateSession(Session{NodeID: "node-a", Username: "alice"})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// A different node records the operator's request; the owning node learns
	// about it through its own heartbeat.
	if err := s.RequestRevocation(sess.ID, "terminated by admin"); err != nil {
		t.Fatalf("RequestRevocation: %v", err)
	}

	revoked, reason, err := s.TouchSession(sess.ID, 0, 0)
	if err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	if !revoked || reason != "terminated by admin" {
		t.Fatalf("heartbeat did not surface the revocation: (%v, %q)", revoked, reason)
	}

	pending, err := s.ListRevokedSessions("node-a")
	if err != nil {
		t.Fatalf("ListRevokedSessions: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != sess.ID {
		t.Fatalf("owning node should see the pending revocation, got %+v", pending)
	}
	other, err := s.ListRevokedSessions("node-b")
	if err != nil {
		t.Fatalf("ListRevokedSessions other node: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("a different node must not be asked to close a session it does not own: %+v", other)
	}
}

func TestRevokeSessionsForUser(t *testing.T) {
	s := newTestStore(t)

	for i := 0; i < 3; i++ {
		if _, err := s.CreateSession(Session{NodeID: "node-a", Username: "mallory"}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}
	if _, err := s.CreateSession(Session{NodeID: "node-a", Username: "alice"}); err != nil {
		t.Fatalf("CreateSession alice: %v", err)
	}

	count, err := s.RevokeSessionsForUser("mallory", "account disabled")
	if err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	if count != 3 {
		t.Fatalf("revoked %d sessions, want 3", count)
	}

	pending, err := s.ListRevokedSessions("node-a")
	if err != nil {
		t.Fatalf("ListRevokedSessions: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("expected 3 sessions marked for disconnection, got %d", len(pending))
	}
	for _, p := range pending {
		if p.Username != "mallory" {
			t.Fatalf("revocation hit an unrelated user's session: %+v", p)
		}
	}
}

func TestCountActiveSessionsBacksConcurrencyLimits(t *testing.T) {
	s := newTestStore(t)

	for i := 0; i < 2; i++ {
		if _, err := s.CreateSession(Session{Username: "alice", TargetID: "tgt-1"}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}
	closed, err := s.CreateSession(Session{Username: "alice", TargetID: "tgt-2"})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := s.CloseSession(closed.ID, SessionClosed, "", 0, 0); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	total, err := s.CountActiveSessions("alice", "")
	if err != nil {
		t.Fatalf("CountActiveSessions: %v", err)
	}
	if total != 2 {
		t.Fatalf("active count = %d, want 2 (closed sessions must not count)", total)
	}

	scoped, err := s.CountActiveSessions("alice", "tgt-1")
	if err != nil {
		t.Fatalf("CountActiveSessions scoped: %v", err)
	}
	if scoped != 2 {
		t.Fatalf("per-target count = %d, want 2", scoped)
	}

	if err := s.CheckConcurrency("alice", "tgt-1", AccessDecision{MaxConcurrent: 2}); err == nil {
		t.Fatal("a third session should exceed a limit of 2")
	}
	if err := s.CheckConcurrency("alice", "tgt-1", AccessDecision{MaxConcurrent: 5}); err != nil {
		t.Fatalf("a limit of 5 should still have room: %v", err)
	}
	if err := s.CheckConcurrency("alice", "tgt-1", AccessDecision{}); err != nil {
		t.Fatalf("an unset limit should not restrict: %v", err)
	}
}

func TestListSessionsFilters(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.CreateSession(Session{Username: "alice", NodeID: "node-a", SourceIP: "10.0.0.1", TargetID: "t1"}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := s.CreateSession(Session{Username: "bob", NodeID: "node-b", SourceIP: "10.0.0.2", TargetID: "t2"}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	closed, err := s.CreateSession(Session{Username: "alice", NodeID: "node-a", TargetID: "t1"})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := s.CloseSession(closed.ID, SessionClosed, "", 0, 0); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	cases := []struct {
		name   string
		filter SessionFilter
		want   int
	}{
		{"all", SessionFilter{}, 3},
		{"active only", SessionFilter{Status: SessionActive}, 2},
		{"by user", SessionFilter{Username: "alice"}, 2},
		{"by user and status", SessionFilter{Username: "alice", Status: SessionActive}, 1},
		{"by node", SessionFilter{NodeID: "node-b"}, 1},
		{"by target", SessionFilter{TargetID: "t1"}, 2},
		{"by source ip", SessionFilter{SourceIP: "10.0.0.2"}, 1},
		{"limit", SessionFilter{Limit: 1}, 1},
		{"no match", SessionFilter{Username: "nobody"}, 0},
	}
	for _, tc := range cases {
		got, err := s.ListSessions(tc.filter)
		if err != nil {
			t.Fatalf("ListSessions(%s): %v", tc.name, err)
		}
		if len(got) != tc.want {
			t.Errorf("ListSessions(%s) returned %d, want %d", tc.name, len(got), tc.want)
		}
	}
}

func TestReapStaleSessions(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })

	stale, err := s.CreateSession(Session{Username: "ghost", NodeID: "crashed-node"})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Move the clock forward so the session's heartbeat is old.
	s.SetClock(func() time.Time { return now.Add(30 * time.Minute) })
	fresh, err := s.CreateSession(Session{Username: "live", NodeID: "healthy-node"})
	if err != nil {
		t.Fatalf("CreateSession fresh: %v", err)
	}

	reaped, err := s.ReapStaleSessions(10 * time.Minute)
	if err != nil {
		t.Fatalf("ReapStaleSessions: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("reaped %d sessions, want 1", reaped)
	}

	got, _ := s.GetSession(stale.ID)
	if got.Status != SessionTerminated {
		t.Fatalf("stale session status = %q, want terminated", got.Status)
	}
	if got.TerminationInfo == "" {
		t.Error("a reaped session should record why it was closed")
	}
	got, _ = s.GetSession(fresh.ID)
	if got.Status != SessionActive {
		t.Fatalf("a recently seen session was reaped: %+v", got)
	}

	// A stale session must stop holding a concurrency slot.
	count, err := s.CountActiveSessions("ghost", "")
	if err != nil {
		t.Fatalf("CountActiveSessions: %v", err)
	}
	if count != 0 {
		t.Fatalf("reaped session still counts as active: %d", count)
	}
}

func TestDeleteSessionsBeforeKeepsActiveRows(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })

	old, err := s.CreateSession(Session{Username: "old"})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := s.CloseSession(old.ID, SessionClosed, "", 0, 0); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	live, err := s.CreateSession(Session{Username: "live"})
	if err != nil {
		t.Fatalf("CreateSession live: %v", err)
	}

	deleted, err := s.DeleteSessionsBefore(now.Add(time.Hour))
	if err != nil {
		t.Fatalf("DeleteSessionsBefore: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted %d rows, want 1", deleted)
	}
	if _, err := s.GetSession(live.ID); err != nil {
		t.Fatalf("an active session must never be pruned: %v", err)
	}
}
