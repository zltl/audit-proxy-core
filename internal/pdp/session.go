package pdp

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"time"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// OpenSession records a session and applies the limits that can only be checked
// against live state.
//
// Concurrency is one of those: policy can say "at most three at once", but only
// a count of what is currently open can enforce it, and that count has to be
// taken in the shared database or every node would enforce its own limit.
func (s *Server) OpenSession(_ context.Context, req *sshproxyv1.OpenSessionRequest) (*sshproxyv1.OpenSessionResponse, error) {
	rule, err := s.loadRule(req.GetRuleId())
	if err != nil {
		return nil, status(err, "load access rule")
	}

	if rule.MaxConcurrent > 0 {
		count, err := s.store.CountActiveSessions(req.GetUsername(), "")
		if err != nil {
			return nil, status(err, "count active sessions")
		}
		if count >= rule.MaxConcurrent {
			return &sshproxyv1.OpenSessionResponse{
				Allowed: false,
				Reason: "session limit reached: " +
					itoa(count) + " of " + itoa(rule.MaxConcurrent) + " already open",
			}, nil
		}
	}

	session, err := s.store.CreateSession(store.Session{
		NodeID:          req.GetClient().GetNodeId(),
		Username:        req.GetUsername(),
		SourceIP:        req.GetClient().GetSourceIp(),
		ClientVersion:   req.GetClient().GetClientVersion(),
		TargetID:        req.GetTargetId(),
		TargetHost:      req.GetTargetHost(),
		TargetPort:      int(req.GetTargetPort()),
		UpstreamLogin:   req.GetUpstreamLogin(),
		Status:          store.SessionActive,
		Features:        rule.Features,
		CommandPolicyID: rule.CommandPolicyID,
		RecordPolicy:    rule.RecordPolicy,
		RuleID:          rule.ID,
		MaxSessionTTL:   rule.MaxSessionTTL,
		IdleTimeout:     rule.IdleTimeout,
	})
	if err != nil {
		return nil, status(err, "create session")
	}
	return &sshproxyv1.OpenSessionResponse{SessionId: session.ID, Allowed: true}, nil
}

// loadRule fetches the rule a session was authorized under. A missing rule is
// not fatal — a just-in-time grant has no rule row — but the resulting session
// then carries no constraints beyond what the caller was already told.
func (s *Server) loadRule(ruleID string) (store.AccessRule, error) {
	if strings.TrimSpace(ruleID) == "" {
		return store.AccessRule{
			Features:     store.FeatureShell | store.FeatureExec | store.FeaturePTY | store.FeatureEnv,
			RecordPolicy: store.RecordFull,
		}, nil
	}
	rule, err := s.store.GetAccessRule(ruleID)
	if errors.Is(err, store.ErrNotFound) {
		return store.AccessRule{
			Features:     store.FeatureShell | store.FeatureExec | store.FeaturePTY | store.FeatureEnv,
			RecordPolicy: store.RecordFull,
		}, nil
	}
	return rule, err
}

// HeartbeatSession refreshes a live session and reports whether it must end.
func (s *Server) HeartbeatSession(_ context.Context, req *sshproxyv1.HeartbeatSessionRequest) (*sshproxyv1.HeartbeatSessionResponse, error) {
	revoked, reason, err := s.store.TouchSession(req.GetSessionId(), req.GetBytesIn(), req.GetBytesOut())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// A session the database no longer considers active must be closed
			// by the node holding it, so it is reported as revoked.
			return &sshproxyv1.HeartbeatSessionResponse{
				Revoked: true,
				Reason:  "session is no longer active",
			}, nil
		}
		return nil, status(err, "heartbeat session")
	}
	if revoked {
		return &sshproxyv1.HeartbeatSessionResponse{Revoked: true, Reason: reason}, nil
	}

	// Time limits are checked on the heartbeat rather than by a sweeper, so a
	// session ends close to its deadline without a separate scheduler.
	session, err := s.store.GetSession(req.GetSessionId())
	if err != nil {
		return &sshproxyv1.HeartbeatSessionResponse{}, nil
	}
	now := s.now()
	if session.ExceededMaxDuration(now) {
		return &sshproxyv1.HeartbeatSessionResponse{
			Revoked: true,
			Reason:  "maximum session duration reached",
		}, nil
	}
	return &sshproxyv1.HeartbeatSessionResponse{}, nil
}

// CloseSession records the end of a session.
func (s *Server) CloseSession(_ context.Context, req *sshproxyv1.CloseSessionRequest) (*sshproxyv1.CloseSessionResponse, error) {
	sessionStatus := store.SessionClosed
	if strings.EqualFold(req.GetStatus(), string(store.SessionTerminated)) {
		sessionStatus = store.SessionTerminated
	}
	if ref := strings.TrimSpace(req.GetRecordingRef()); ref != "" {
		if err := s.store.SetRecordingRef(req.GetSessionId(), ref); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			log.Printf("pdp: record recording reference for %s: %v", req.GetSessionId(), err)
		}
	}
	err := s.store.CloseSession(req.GetSessionId(), sessionStatus,
		req.GetTerminationInfo(), req.GetBytesIn(), req.GetBytesOut())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, status(err, "close session")
	}
	return &sshproxyv1.CloseSessionResponse{}, nil
}

// revocationPollInterval is how often the stream checks for new termination
// requests. Heartbeats also carry the flag, so this interval bounds how long a
// node waits when it happens to be idle rather than how long a kill takes.
const revocationPollInterval = 2 * time.Second

// StreamRevocations pushes termination requests to the node that owns them.
func (s *Server) StreamRevocations(req *sshproxyv1.StreamRevocationsRequest, stream sshproxyv1.AccessDecisionService_StreamRevocationsServer) error {
	nodeID := strings.TrimSpace(req.GetNodeId())
	if nodeID == "" {
		return errors.New("pdp: node_id is required to receive revocations")
	}

	ctx := stream.Context()
	ticker := time.NewTicker(revocationPollInterval)
	defer ticker.Stop()

	// Sent sessions are remembered so a revocation that the node has not yet
	// acted on is not re-sent every tick.
	sent := make(map[string]bool)

	for {
		sessions, err := s.store.ListRevokedSessions(nodeID)
		if err != nil {
			return status(err, "list revoked sessions")
		}
		live := make(map[string]bool, len(sessions))
		for _, session := range sessions {
			live[session.ID] = true
			if sent[session.ID] {
				continue
			}
			if err := stream.Send(&sshproxyv1.Revocation{
				SessionId:   session.ID,
				Reason:      session.RevokeReason,
				RequestedAt: timestamp(s.now()),
			}); err != nil {
				return err
			}
			sent[session.ID] = true
		}
		// Forget sessions that are gone, so the map does not grow without bound
		// on a long-lived stream.
		for id := range sent {
			if !live[id] {
				delete(sent, id)
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// ReportEvents accepts batches of audit records from a data-plane node.
func (s *Server) ReportEvents(stream sshproxyv1.AccessDecisionService_ReportEventsServer) error {
	var accepted int64
	for {
		batch, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&sshproxyv1.ReportEventsResponse{Accepted: accepted})
		}
		if err != nil {
			return err
		}
		if s.sink == nil {
			// Without a sink the events would be dropped. Reporting zero accepted
			// tells the sender to keep them spooled rather than assume delivery.
			continue
		}
		if err := s.sink.Publish(stream.Context(), batch.GetEvents()); err != nil {
			return status(err, "publish audit events")
		}
		accepted += int64(len(batch.GetEvents()))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
