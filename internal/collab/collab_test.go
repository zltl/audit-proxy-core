package collab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Session Manager Tests ---

func TestCreateSession(t *testing.T) {
	m := NewManager()
	s, err := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.SessionID != "sess-1" {
		t.Errorf("expected session_id=sess-1, got %s", s.SessionID)
	}
	if s.Owner != "alice" {
		t.Errorf("expected owner=alice, got %s", s.Owner)
	}
	if s.Status != "active" {
		t.Errorf("expected status=active, got %s", s.Status)
	}
	if len(s.Participants) != 1 {
		t.Fatalf("expected 1 participant, got %d", len(s.Participants))
	}
	if s.Participants[0].Role != RoleOwner {
		t.Errorf("expected owner role, got %s", s.Participants[0].Role)
	}
	if s.MaxViewers != 5 {
		t.Errorf("expected max_viewers=5, got %d", s.MaxViewers)
	}
	if !s.AllowControl {
		t.Error("expected allow_control=true")
	}
}

func TestCreateSessionValidation(t *testing.T) {
	m := NewManager()
	_, err := m.CreateSession("", "alice", "server-1", 5, true)
	if err == nil {
		t.Error("expected error for empty session_id")
	}
	_, err = m.CreateSession("sess-1", "", "server-1", 5, true)
	if err == nil {
		t.Error("expected error for empty owner")
	}
}

func TestGetSession(t *testing.T) {
	m := NewManager()
	created, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)

	got, err := m.GetSession(created.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID=%s, got %s", created.ID, got.ID)
	}

	_, err = m.GetSession("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

func TestListSessions(t *testing.T) {
	m := NewManager()
	m.CreateSession("s1", "alice", "srv1", 5, true)
	m.CreateSession("s2", "bob", "srv2", 5, true)

	sessions := m.ListSessions()
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestJoinSession(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)

	err := m.JoinSession(s.ID, "bob", RoleViewer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.mu.RLock()
	if len(s.Participants) != 2 {
		t.Errorf("expected 2 participants, got %d", len(s.Participants))
	}
	s.mu.RUnlock()
}

func TestJoinSessionDuplicate(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)

	m.JoinSession(s.ID, "bob", RoleViewer)
	err := m.JoinSession(s.ID, "bob", RoleViewer)
	if err == nil {
		t.Error("expected error for duplicate join")
	}
}

func TestJoinSessionAsOwner(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)

	err := m.JoinSession(s.ID, "bob", RoleOwner)
	if err == nil {
		t.Error("expected error when joining as owner")
	}
}

func TestLeaveSession(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	err := m.LeaveSession(s.ID, "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.mu.RLock()
	if len(s.Participants) != 1 {
		t.Errorf("expected 1 participant after leave, got %d", len(s.Participants))
	}
	s.mu.RUnlock()

	err = m.LeaveSession(s.ID, "bob")
	if err == nil {
		t.Error("expected error for leaving when not in session")
	}
}

func TestEndSession(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	err := m.EndSession(s.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.Status != "ended" {
		t.Errorf("expected status=ended, got %s", s.Status)
	}

	// Cannot broadcast to ended session
	err = m.Broadcast(s.ID, []byte("hello"))
	if err == nil {
		t.Error("expected error broadcasting to ended session")
	}
}

func TestBroadcastAndSubscribe(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	ch, err := m.Subscribe(s.ID, "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := []byte("terminal output data")
	err = m.Broadcast(s.ID, data)
	if err != nil {
		t.Fatalf("broadcast error: %v", err)
	}

	select {
	case received := <-ch:
		if string(received) != string(data) {
			t.Errorf("expected %q, got %q", data, received)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for broadcast data")
	}
}

func TestSubscribeNotInSession(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)

	_, err := m.Subscribe(s.ID, "stranger")
	if err == nil {
		t.Error("expected error subscribing when not in session")
	}
}

func TestMaxViewersLimit(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 2, true)

	m.JoinSession(s.ID, "viewer1", RoleViewer)
	m.JoinSession(s.ID, "viewer2", RoleViewer)

	err := m.JoinSession(s.ID, "viewer3", RoleViewer)
	if err == nil {
		t.Error("expected error when max viewers reached")
	}
	if !strings.Contains(err.Error(), "maximum viewers") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestControl(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	err := m.RequestControl(s.ID, "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Owner already has control
	err = m.RequestControl(s.ID, "alice")
	if err == nil {
		t.Error("expected error: owner already has control")
	}
}

func TestRequestControlNotAllowed(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, false)
	m.JoinSession(s.ID, "bob", RoleViewer)

	err := m.RequestControl(s.ID, "bob")
	if err == nil {
		t.Error("expected error: control sharing not allowed")
	}
}

func TestGrantControl(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	err := m.GrantControl(s.ID, "alice", "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.mu.RLock()
	var bobRole ParticipantRole
	for _, p := range s.Participants {
		if p.Username == "bob" {
			bobRole = p.Role
		}
	}
	s.mu.RUnlock()

	if bobRole != RoleOperator {
		t.Errorf("expected bob to be operator, got %s", bobRole)
	}
}

func TestGrantControlNonOwner(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)
	m.JoinSession(s.ID, "charlie", RoleViewer)

	err := m.GrantControl(s.ID, "bob", "charlie")
	if err == nil {
		t.Error("expected error: only owner can grant control")
	}
}

func TestRevokeControl(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)
	m.GrantControl(s.ID, "alice", "bob")

	err := m.RevokeControl(s.ID, "alice", "bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.mu.RLock()
	var bobRole ParticipantRole
	for _, p := range s.Participants {
		if p.Username == "bob" {
			bobRole = p.Role
		}
	}
	s.mu.RUnlock()

	if bobRole != RoleViewer {
		t.Errorf("expected bob to be viewer after revoke, got %s", bobRole)
	}
}

func TestRevokeControlFromOwner(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)

	err := m.RevokeControl(s.ID, "alice", "alice")
	if err == nil {
		t.Error("expected error: cannot revoke control from owner")
	}
}

func TestFourEyesGrantControlApprovalFlow(t *testing.T) {
	m := NewManager()
	s, err := m.CreateSessionWithOptions("sess-1", "alice", "server-1", SessionOptions{
		MaxViewers:       5,
		AllowControl:     true,
		FourEyesRequired: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := m.JoinSession(s.ID, "bob", RoleViewer); err != nil {
		t.Fatalf("join error: %v", err)
	}

	if err := m.GrantControl(s.ID, "alice", "bob"); err == nil {
		t.Fatal("expected direct grant to require four-eyes approval")
	}

	approval, err := m.RequestActionApproval(s.ID, "alice", SessionActionGrantControl, "bob")
	if err != nil {
		t.Fatalf("request approval error: %v", err)
	}
	if approval.Status != "pending" {
		t.Fatalf("expected pending approval, got %+v", approval)
	}

	if _, err := m.ApproveAction(s.ID, approval.ID, "alice"); err == nil {
		t.Fatal("expected requester self-approval to be rejected")
	}

	approved, err := m.ApproveAction(s.ID, approval.ID, "bob")
	if err != nil {
		t.Fatalf("approve action error: %v", err)
	}
	if approved.Status != "approved" || approved.Approver != "bob" {
		t.Fatalf("unexpected approved action: %+v", approved)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	var bobRole ParticipantRole
	for _, p := range s.Participants {
		if p.Username == "bob" {
			bobRole = p.Role
		}
	}
	if bobRole != RoleOperator {
		t.Fatalf("expected bob to be operator, got %s", bobRole)
	}
}

func TestFourEyesApprovalRequiresSecondParticipantPresence(t *testing.T) {
	m := NewManager()
	s, err := m.CreateSessionWithOptions("sess-1", "alice", "server-1", SessionOptions{
		MaxViewers:       5,
		AllowControl:     true,
		FourEyesRequired: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := m.RequestActionApproval(s.ID, "alice", SessionActionEndSession, ""); err == nil {
		t.Fatal("expected approval request to fail without a second participant")
	}

	if err := m.JoinSession(s.ID, "bob", RoleViewer); err != nil {
		t.Fatalf("join error: %v", err)
	}
	approval, err := m.RequestActionApproval(s.ID, "alice", SessionActionEndSession, "")
	if err != nil {
		t.Fatalf("request approval error: %v", err)
	}
	if err := m.LeaveSession(s.ID, "bob"); err != nil {
		t.Fatalf("leave error: %v", err)
	}
	if _, err := m.ApproveAction(s.ID, approval.ID, "bob"); err == nil {
		t.Fatal("expected approval to fail once the second participant leaves")
	}
}

func TestViewerCannotTypeWithoutGrant(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	s.mu.RLock()
	var bobRole ParticipantRole
	for _, p := range s.Participants {
		if p.Username == "bob" {
			bobRole = p.Role
		}
	}
	s.mu.RUnlock()

	if bobRole != RoleViewer {
		t.Errorf("expected bob to be viewer, got %s", bobRole)
	}

	// After granting control, bob becomes operator
	m.GrantControl(s.ID, "alice", "bob")

	s.mu.RLock()
	for _, p := range s.Participants {
		if p.Username == "bob" {
			bobRole = p.Role
		}
	}
	s.mu.RUnlock()

	if bobRole != RoleOperator {
		t.Errorf("expected bob to be operator after grant, got %s", bobRole)
	}
}

// --- Chat Tests ---

func TestChatSendMessage(t *testing.T) {
	cr := NewChatRoom("sess-1", 100)
	msg := cr.SendMessage("alice", "hello world")

	if msg.Username != "alice" {
		t.Errorf("expected username=alice, got %s", msg.Username)
	}
	if msg.Message != "hello world" {
		t.Errorf("expected message='hello world', got %s", msg.Message)
	}
	if msg.Type != "message" {
		t.Errorf("expected type=message, got %s", msg.Type)
	}
	if msg.ID == "" {
		t.Error("expected non-empty message ID")
	}
	if msg.SessionID != "sess-1" {
		t.Errorf("expected session_id=sess-1, got %s", msg.SessionID)
	}
}

func TestChatSystemMessage(t *testing.T) {
	cr := NewChatRoom("sess-1", 100)
	msg := cr.SystemMessage("bob joined the session")

	if msg.Type != "system" {
		t.Errorf("expected type=system, got %s", msg.Type)
	}
	if msg.Username != "system" {
		t.Errorf("expected username=system, got %s", msg.Username)
	}
}

func TestChatGetHistory(t *testing.T) {
	cr := NewChatRoom("sess-1", 100)
	cr.SendMessage("alice", "msg1")
	cr.SendMessage("bob", "msg2")
	cr.SendMessage("alice", "msg3")

	// Get all
	history := cr.GetHistory(0)
	if len(history) != 3 {
		t.Errorf("expected 3 messages, got %d", len(history))
	}

	// Get limited
	history = cr.GetHistory(2)
	if len(history) != 2 {
		t.Errorf("expected 2 messages, got %d", len(history))
	}
	if history[0].Message != "msg2" {
		t.Errorf("expected msg2, got %s", history[0].Message)
	}
}

func TestChatMaxMessages(t *testing.T) {
	cr := NewChatRoom("sess-1", 3)
	cr.SendMessage("a", "1")
	cr.SendMessage("a", "2")
	cr.SendMessage("a", "3")
	cr.SendMessage("a", "4")

	history := cr.GetHistory(0)
	if len(history) != 3 {
		t.Errorf("expected 3 messages (capped), got %d", len(history))
	}
	if history[0].Message != "2" {
		t.Errorf("expected oldest message to be '2', got %s", history[0].Message)
	}
}

func TestChatSubscribeReceive(t *testing.T) {
	cr := NewChatRoom("sess-1", 100)
	ch := cr.Subscribe("bob")

	cr.SendMessage("alice", "hello bob")

	select {
	case msg := <-ch:
		if msg.Message != "hello bob" {
			t.Errorf("expected 'hello bob', got %s", msg.Message)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for chat message")
	}
}

func TestChatUnsubscribe(t *testing.T) {
	cr := NewChatRoom("sess-1", 100)
	ch := cr.Subscribe("bob")
	cr.Unsubscribe("bob")

	// Channel should be closed
	_, ok := <-ch
	if ok {
		t.Error("expected channel to be closed after unsubscribe")
	}
}

// --- Recording Tests ---

func TestRecordingEvents(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder("sess-1", dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rec.Close()

	rec.RecordOutput("$ ls\nfile1 file2\n")
	rec.RecordInput("alice", "ls\n")
	rec.RecordJoin("bob")
	rec.RecordLeave("bob")
	rec.RecordChat("alice", "hello")
	rec.RecordControlChange("alice", "bob")

	events := rec.Events()
	if len(events) != 6 {
		t.Fatalf("expected 6 events, got %d", len(events))
	}

	expectedTypes := []string{"output", "input", "join", "leave", "chat", "control"}
	for i, et := range expectedTypes {
		if events[i].Type != et {
			t.Errorf("event %d: expected type=%s, got %s", i, et, events[i].Type)
		}
	}

	if events[1].Username != "alice" {
		t.Errorf("expected input username=alice, got %s", events[1].Username)
	}

	// Verify time is monotonically increasing
	for i := 1; i < len(events); i++ {
		if events[i].Time < events[i-1].Time {
			t.Errorf("event %d time (%f) < event %d time (%f)", i, events[i].Time, i-1, events[i-1].Time)
		}
	}
}

func TestRecordingNDJSON(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder("sess-1", dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec.RecordOutput("hello")
	rec.RecordInput("alice", "world")
	rec.Close()

	data, err := os.ReadFile(filepath.Join(dir, "sess-1.jsonl"))
	if err != nil {
		t.Fatalf("failed to read recording file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d", len(lines))
	}

	var event1 RecordingEvent
	if err := json.Unmarshal([]byte(lines[0]), &event1); err != nil {
		t.Fatalf("failed to parse NDJSON line 1: %v", err)
	}
	if event1.Type != "output" {
		t.Errorf("expected type=output, got %s", event1.Type)
	}

	var event2 RecordingEvent
	if err := json.Unmarshal([]byte(lines[1]), &event2); err != nil {
		t.Fatalf("failed to parse NDJSON line 2: %v", err)
	}
	if event2.Type != "input" || event2.Username != "alice" {
		t.Errorf("unexpected event2: %+v", event2)
	}
}

// --- Concurrency Tests ---

func TestConcurrentParticipants(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 100, true)

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	// Join 20 viewers concurrently
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			username := "viewer" + strings.Repeat("x", 0) + string(rune('A'+idx))
			if err := m.JoinSession(s.ID, username, RoleViewer); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent join error: %v", err)
	}

	s.mu.RLock()
	count := len(s.Participants)
	s.mu.RUnlock()

	// 1 owner + 20 viewers
	if count != 21 {
		t.Errorf("expected 21 participants, got %d", count)
	}
}

func TestConcurrentBroadcast(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 100, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	ch, _ := m.Subscribe(s.ID, "bob")

	var wg sync.WaitGroup
	// Broadcast 50 messages concurrently
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			m.Broadcast(s.ID, []byte("msg"))
		}(i)
	}
	wg.Wait()

	// Drain and count received
	received := 0
	done := time.After(time.Second)
	for {
		select {
		case <-ch:
			received++
		case <-done:
			goto check
		}
	}
check:
	if received != 50 {
		t.Errorf("expected 50 messages, received %d", received)
	}
}

func TestEndSessionCleanup(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	bobCh, _ := m.Subscribe(s.ID, "bob")

	m.EndSession(s.ID)

	// Subscriber channel should be closed
	_, ok := <-bobCh
	if ok {
		t.Error("expected bob's channel to be closed after session end")
	}

	// Cannot join ended session
	err := m.JoinSession(s.ID, "charlie", RoleViewer)
	if err == nil {
		t.Error("expected error joining ended session")
	}
}

func TestOwnerPermissions(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)
	m.JoinSession(s.ID, "bob", RoleViewer)

	// Non-owner cannot grant control
	err := m.GrantControl(s.ID, "bob", "bob")
	if err == nil {
		t.Error("expected error: non-owner should not grant control")
	}

	// Non-owner cannot revoke control
	m.GrantControl(s.ID, "alice", "bob")
	err = m.RevokeControl(s.ID, "bob", "bob")
	if err == nil {
		t.Error("expected error: non-owner should not revoke control")
	}
}

func TestSessionJSONSerialization(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("failed to marshal session: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal session: %v", err)
	}

	if result["owner"] != "alice" {
		t.Errorf("expected owner=alice in JSON, got %v", result["owner"])
	}
	if result["status"] != "active" {
		t.Errorf("expected status=active in JSON, got %v", result["status"])
	}
}

func TestOperatorCanJoin(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("sess-1", "alice", "server-1", 5, true)

	err := m.JoinSession(s.ID, "bob", RoleOperator)
	if err != nil {
		t.Fatalf("unexpected error joining as operator: %v", err)
	}

	s.mu.RLock()
	var bobRole ParticipantRole
	for _, p := range s.Participants {
		if p.Username == "bob" {
			bobRole = p.Role
		}
	}
	s.mu.RUnlock()

	if bobRole != RoleOperator {
		t.Errorf("expected bob to be operator, got %s", bobRole)
	}
}
