package pdp

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	auditproxyv1 "github.com/zltl/audit-proxy-core/api/proto/auditproxy/v1"
	"github.com/zltl/audit-proxy-core/internal/store"
)

func TestOpenSessionCarriesRuleConstraints(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{
		ID: "r1", Features: store.FeatureShell | store.FeatureSFTP,
		CommandPolicyID: "cp-1", RecordPolicy: store.RecordCommands,
		MaxSessionTTL: time.Hour, IdleTimeout: 5 * time.Minute,
	})

	resp, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client:        &auditproxyv1.ClientInfo{NodeId: "node-a", SourceIp: "10.0.0.5"},
		Username:      "alice",
		TargetId:      f.target.ID,
		TargetHost:    f.target.Host,
		TargetPort:    int32(f.target.Port),
		UpstreamLogin: "deploy",
		RuleId:        rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if !resp.GetAllowed() || resp.GetSessionId() == "" {
		t.Fatalf("OpenSession = %+v", resp)
	}

	// The constraints must be on the row, so any node can answer questions
	// about this session without holding state.
	session, err := f.store.GetSession(resp.GetSessionId())
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !session.Features.Has(store.FeatureSFTP) || session.Features.Has(store.FeatureLocalForward) {
		t.Errorf("features not recorded on the session: %s", session.Features)
	}
	if session.CommandPolicyID != "cp-1" || session.RecordPolicy != store.RecordCommands {
		t.Errorf("policy attributes not recorded: %+v", session)
	}
	if session.MaxSessionTTL != time.Hour || session.IdleTimeout != 5*time.Minute {
		t.Errorf("time limits not recorded: %v / %v", session.MaxSessionTTL, session.IdleTimeout)
	}
	if session.RuleID != rule.ID {
		t.Errorf("deciding rule not recorded: %q", session.RuleID)
	}
}

func TestOpenSessionEnforcesConcurrencyLimit(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{
		ID: "r1", Features: store.FeatureShell, MaxConcurrent: 2,
	})

	open := func() *auditproxyv1.OpenSessionResponse {
		t.Helper()
		resp, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
			Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
			TargetId: f.target.ID, RuleId: rule.ID,
		})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		return resp
	}

	first := open()
	second := open()
	if !first.GetAllowed() || !second.GetAllowed() {
		t.Fatal("the first two sessions should be within the limit")
	}
	third := open()
	if third.GetAllowed() {
		t.Fatal("a third session exceeded a limit of two")
	}
	if !strings.Contains(third.GetReason(), "limit") {
		t.Errorf("the refusal should explain the limit, got %q", third.GetReason())
	}

	// Closing one frees a slot.
	if err := f.store.CloseSession(first.GetSessionId(), store.SessionClosed, "", 0, 0); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if !open().GetAllowed() {
		t.Fatal("closing a session should free a slot")
	}
}

func TestHeartbeatSurfacesRevocation(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	beat, err := f.server.HeartbeatSession(context.Background(), &auditproxyv1.HeartbeatSessionRequest{
		SessionId: opened.GetSessionId(), BytesIn: 100, BytesOut: 200,
	})
	if err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}
	if beat.GetRevoked() {
		t.Fatal("a healthy session was told to disconnect")
	}

	if err := f.store.RequestRevocation(opened.GetSessionId(), "terminated by admin"); err != nil {
		t.Fatalf("RequestRevocation: %v", err)
	}
	beat, err = f.server.HeartbeatSession(context.Background(), &auditproxyv1.HeartbeatSessionRequest{
		SessionId: opened.GetSessionId(),
	})
	if err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}
	if !beat.GetRevoked() || beat.GetReason() != "terminated by admin" {
		t.Fatalf("heartbeat did not surface the revocation: %+v", beat)
	}
}

func TestHeartbeatEnforcesMaxDuration(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{
		ID: "r1", Features: store.FeatureShell, MaxSessionTTL: 30 * time.Minute,
	})

	base := time.Now().UTC()
	f.store.SetClock(func() time.Time { return base })
	f.server.SetClock(func() time.Time { return base })

	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	later := base.Add(31 * time.Minute)
	f.store.SetClock(func() time.Time { return later })
	f.server.SetClock(func() time.Time { return later })

	beat, err := f.server.HeartbeatSession(context.Background(), &auditproxyv1.HeartbeatSessionRequest{
		SessionId: opened.GetSessionId(),
	})
	if err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}
	if !beat.GetRevoked() {
		t.Fatal("a session past its maximum duration should be told to disconnect")
	}
	if !strings.Contains(beat.GetReason(), "duration") {
		t.Errorf("reason = %q, want it to mention the duration limit", beat.GetReason())
	}
}

func TestHeartbeatOnUnknownSessionAsksToDisconnect(t *testing.T) {
	f := newFixture(t)
	beat, err := f.server.HeartbeatSession(context.Background(), &auditproxyv1.HeartbeatSessionRequest{
		SessionId: "no-such-session",
	})
	if err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}
	if !beat.GetRevoked() {
		t.Fatal("a session the database does not know about must be closed by whoever holds it")
	}
}

func TestCloseSessionRecordsOutcome(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	if _, err := f.server.CloseSession(context.Background(), &auditproxyv1.CloseSessionRequest{
		SessionId: opened.GetSessionId(), BytesIn: 10, BytesOut: 20,
		Status: "terminated", TerminationInfo: "revoked by operator",
		RecordingRef: "s3://bucket/sess.cast",
	}); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	session, err := f.store.GetSession(opened.GetSessionId())
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if session.Status != store.SessionTerminated {
		t.Errorf("status = %q, want terminated", session.Status)
	}
	if session.RecordingRef != "s3://bucket/sess.cast" {
		t.Errorf("recording reference = %q", session.RecordingRef)
	}
	if session.BytesIn != 10 || session.BytesOut != 20 {
		t.Errorf("byte counters = %d/%d", session.BytesIn, session.BytesOut)
	}
	if session.TerminationInfo == "" {
		t.Error("the reason for termination was not recorded")
	}
}

// revocationStream captures what StreamRevocations pushes.
type revocationStream struct {
	auditproxyv1.AccessDecisionService_StreamRevocationsServer
	ctx      context.Context
	mu       sync.Mutex
	received []*auditproxyv1.Revocation
	notify   chan struct{}
}

func newRevocationStream(ctx context.Context) *revocationStream {
	return &revocationStream{ctx: ctx, notify: make(chan struct{}, 16)}
}

func (s *revocationStream) Send(rev *auditproxyv1.Revocation) error {
	s.mu.Lock()
	s.received = append(s.received, rev)
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return nil
}
func (s *revocationStream) Context() context.Context     { return s.ctx }
func (s *revocationStream) SetHeader(metadata.MD) error  { return nil }
func (s *revocationStream) SendHeader(metadata.MD) error { return nil }
func (s *revocationStream) SetTrailer(metadata.MD)       {}

func (s *revocationStream) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.received)
}

func TestStreamRevocationsDeliversToTheOwningNodeOnly(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if err := f.store.RequestRevocation(opened.GetSessionId(), "terminated by admin"); err != nil {
		t.Fatalf("RequestRevocation: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	owner := newRevocationStream(ctx)
	done := make(chan error, 1)
	go func() {
		done <- f.server.StreamRevocations(&auditproxyv1.StreamRevocationsRequest{NodeId: "node-a"}, owner)
	}()

	select {
	case <-owner.notify:
	case <-ctx.Done():
		t.Fatal("the owning node was never told to disconnect the session")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("StreamRevocations: %v", err)
	}
	if owner.received[0].GetSessionId() != opened.GetSessionId() {
		t.Fatalf("wrong session delivered: %+v", owner.received[0])
	}

	// A node that does not own the session must not be asked to close it.
	otherCtx, otherCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer otherCancel()
	other := newRevocationStream(otherCtx)
	if err := f.server.StreamRevocations(&auditproxyv1.StreamRevocationsRequest{NodeId: "node-b"}, other); err != nil {
		t.Fatalf("StreamRevocations other node: %v", err)
	}
	if other.count() != 0 {
		t.Fatalf("a node was asked to close a session it does not own: %+v", other.received)
	}
}

func TestStreamRevocationsDoesNotRepeat(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if err := f.store.RequestRevocation(opened.GetSessionId(), "stop"); err != nil {
		t.Fatalf("RequestRevocation: %v", err)
	}

	// Run long enough for several poll intervals to elapse.
	ctx, cancel := context.WithTimeout(context.Background(), revocationPollInterval*2+time.Second)
	defer cancel()
	stream := newRevocationStream(ctx)
	if err := f.server.StreamRevocations(&auditproxyv1.StreamRevocationsRequest{NodeId: "node-a"}, stream); err != nil {
		t.Fatalf("StreamRevocations: %v", err)
	}
	if got := stream.count(); got != 1 {
		t.Fatalf("the same revocation was delivered %d times; a node would be spammed", got)
	}
}

func TestStreamRevocationsRequiresANodeID(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := f.server.StreamRevocations(&auditproxyv1.StreamRevocationsRequest{}, newRevocationStream(ctx))
	if err == nil {
		t.Fatal("a stream without a node id should be refused; it cannot be routed")
	}
}

// --------------------------------------------------------------------------
// Host keys
// --------------------------------------------------------------------------

func TestResolveHostKeyPinned(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.PutHostKey(store.HostKey{
		TargetID: f.target.ID, Algorithm: "ssh-ed25519", PublicKey: "AAAA",
		Fingerprint: "SHA256:known", Status: store.HostKeyTrusted,
	}); err != nil {
		t.Fatalf("PutHostKey: %v", err)
	}

	resp, err := f.server.ResolveHostKey(context.Background(), &auditproxyv1.ResolveHostKeyRequest{
		TargetId: f.target.ID, Fingerprint: "SHA256:known",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if resp.GetVerdict() != auditproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_TRUSTED || !resp.GetProceed() {
		t.Fatalf("a pinned key was not trusted: %+v", resp)
	}
}

func TestResolveHostKeyRejectsRevokedAndMismatched(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.PutHostKey(store.HostKey{
		TargetID: f.target.ID, Fingerprint: "SHA256:good", Status: store.HostKeyTrusted,
	}); err != nil {
		t.Fatalf("PutHostKey: %v", err)
	}
	if _, err := f.store.PutHostKey(store.HostKey{
		TargetID: f.target.ID, Fingerprint: "SHA256:retired", Status: store.HostKeyRevoked,
	}); err != nil {
		t.Fatalf("PutHostKey revoked: %v", err)
	}

	revoked, err := f.server.ResolveHostKey(context.Background(), &auditproxyv1.ResolveHostKeyRequest{
		TargetId: f.target.ID, Fingerprint: "SHA256:retired",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if revoked.GetProceed() {
		t.Fatal("a revoked host key was accepted")
	}

	// A target that already has pinned keys presenting a different one is the
	// shape of an interception and must not proceed.
	mismatch, err := f.server.ResolveHostKey(context.Background(), &auditproxyv1.ResolveHostKeyRequest{
		TargetId: f.target.ID, Fingerprint: "SHA256:unexpected", PublicKey: "BBBB",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if mismatch.GetProceed() {
		t.Fatal("an unexpected host key was accepted for a target with pinned keys")
	}
	if mismatch.GetVerdict() != auditproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_REJECTED {
		t.Errorf("verdict = %v, want REJECTED", mismatch.GetVerdict())
	}
}

func TestResolveHostKeyFirstContact(t *testing.T) {
	f := newFixture(t)

	// Default: record it, but do not proceed on an unverified key.
	resp, err := f.server.ResolveHostKey(context.Background(), &auditproxyv1.ResolveHostKeyRequest{
		TargetId: f.target.ID, Algorithm: "ssh-ed25519", PublicKey: "AAAA",
		Fingerprint: "SHA256:first",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if resp.GetProceed() {
		t.Fatal("an unknown host key was accepted with trust-on-first-use disabled")
	}
	if resp.GetVerdict() != auditproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_PENDING {
		t.Errorf("verdict = %v, want PENDING", resp.GetVerdict())
	}

	pending, err := f.store.ListPendingHostKeys()
	if err != nil {
		t.Fatalf("ListPendingHostKeys: %v", err)
	}
	if len(pending) != 1 || pending[0].Fingerprint != "SHA256:first" {
		t.Fatalf("the key should have been recorded for review, got %+v", pending)
	}

	// With trust-on-first-use the same key is accepted, still pending review.
	f.server.config.TrustOnFirstUse = true
	resp, err = f.server.ResolveHostKey(context.Background(), &auditproxyv1.ResolveHostKeyRequest{
		TargetId: f.target.ID, Fingerprint: "SHA256:first",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if !resp.GetProceed() {
		t.Fatal("trust-on-first-use should let the connection proceed")
	}
}

func TestResolveHostKeyUnknownTarget(t *testing.T) {
	f := newFixture(t)
	resp, err := f.server.ResolveHostKey(context.Background(), &auditproxyv1.ResolveHostKeyRequest{
		TargetHost: "192.0.2.99", TargetPort: 22, Fingerprint: "SHA256:x",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if resp.GetProceed() {
		t.Fatal("a host that is not a registered target was accepted")
	}
}

func TestResolveHostCertificateScopedToItsAuthority(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.PutHostCA(store.HostCA{
		Name: "prod", PublicKey: "AAAA", Fingerprint: "SHA256:ca",
		HostPatterns: []string{"*.prod.example.com"},
	}); err != nil {
		t.Fatalf("PutHostCA: %v", err)
	}

	inScope, err := f.server.ResolveHostKey(context.Background(), &auditproxyv1.ResolveHostKeyRequest{
		TargetId: f.target.ID, TargetHost: "web1.prod.example.com",
		Fingerprint: "SHA256:whatever", IsCertificate: true, CaFingerprint: "SHA256:ca",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if !inScope.GetProceed() {
		t.Fatalf("a certificate from a trusted authority for a matching host was refused: %s",
			inScope.GetReason())
	}

	// The same authority must not vouch for a host outside its scope.
	outOfScope, err := f.server.ResolveHostKey(context.Background(), &auditproxyv1.ResolveHostKeyRequest{
		TargetId: f.target.ID, TargetHost: "web1.staging.example.com",
		Fingerprint: "SHA256:other", IsCertificate: true, CaFingerprint: "SHA256:ca",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if outOfScope.GetProceed() {
		t.Fatal("a host CA scoped to one environment vouched for another")
	}
}

// --------------------------------------------------------------------------
// Upstream credentials
// --------------------------------------------------------------------------

type recordingSigner struct {
	principals []string
	ttl        time.Duration
}

func (s *recordingSigner) SignUpstreamCertificate(_ string, principals []string, ttl time.Duration) (string, time.Time, error) {
	s.principals = principals
	s.ttl = ttl
	return "ssh-ed25519-cert-v01@openssh.com AAAA", time.Now().Add(ttl), nil
}

func TestIssueUpstreamCredentialCertificate(t *testing.T) {
	f := newFixture(t)
	signer := &recordingSigner{}
	f.server.SetCertificateSigner(signer)

	if _, err := f.store.PutCredential(store.Credential{
		TargetID: f.target.ID, Login: "deploy", Kind: store.CredentialCACert,
	}); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, UpstreamLogin: "deploy", RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	resp, err := f.server.IssueUpstreamCredential(context.Background(), &auditproxyv1.IssueUpstreamCredentialRequest{
		SessionId: opened.GetSessionId(), PublicKey: "ssh-ed25519 AAAA ephemeral",
	})
	if err != nil {
		t.Fatalf("IssueUpstreamCredential: %v", err)
	}
	if resp.GetKind() != auditproxyv1.CredentialKind_CREDENTIAL_KIND_CERTIFICATE {
		t.Fatalf("kind = %v", resp.GetKind())
	}
	if resp.GetCertificate() == "" {
		t.Fatal("no certificate was returned")
	}
	if len(signer.principals) != 1 || signer.principals[0] != "deploy" {
		t.Fatalf("certificate principals = %v, want [deploy]", signer.principals)
	}
	if signer.ttl > time.Hour {
		t.Errorf("a session certificate should be short lived, got %v", signer.ttl)
	}
}

func TestIssueUpstreamCredentialUsesTheAuthorizedAccount(t *testing.T) {
	f := newFixture(t)
	f.server.SetCertificateSigner(&recordingSigner{})

	// Two accounts exist on the target; the session was authorized for one.
	for _, login := range []string{"deploy", "root"} {
		if _, err := f.store.PutCredential(store.Credential{
			TargetID: f.target.ID, Login: login, Kind: store.CredentialCACert,
		}); err != nil {
			t.Fatalf("PutCredential %s: %v", login, err)
		}
	}
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, UpstreamLogin: "deploy", RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	signer := &recordingSigner{}
	f.server.SetCertificateSigner(signer)
	// Asking for root must not produce a root credential: the session was
	// authorized for deploy, and that is what the decision point honours.
	if _, err := f.server.IssueUpstreamCredential(context.Background(), &auditproxyv1.IssueUpstreamCredentialRequest{
		SessionId: opened.GetSessionId(), UpstreamLogin: "root", PublicKey: "ssh-ed25519 AAAA",
	}); err != nil {
		t.Fatalf("IssueUpstreamCredential: %v", err)
	}
	if len(signer.principals) != 1 || signer.principals[0] != "deploy" {
		t.Fatalf("credential was issued for %v, but the session was authorized for deploy",
			signer.principals)
	}
}

func TestIssueUpstreamCredentialDecryptsStoredMaterial(t *testing.T) {
	f := newFixture(t)
	ref, err := f.store.PutSecretString("upstream_password", "vaulted-password")
	if err != nil {
		t.Fatalf("PutSecretString: %v", err)
	}
	if _, err := f.store.PutCredential(store.Credential{
		TargetID: f.target.ID, Login: "svc", Kind: store.CredentialPassword, SecretRef: ref,
	}); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, UpstreamLogin: "svc", RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	resp, err := f.server.IssueUpstreamCredential(context.Background(), &auditproxyv1.IssueUpstreamCredentialRequest{
		SessionId: opened.GetSessionId(),
	})
	if err != nil {
		t.Fatalf("IssueUpstreamCredential: %v", err)
	}
	if resp.GetKind() != auditproxyv1.CredentialKind_CREDENTIAL_KIND_PASSWORD {
		t.Fatalf("kind = %v", resp.GetKind())
	}
	if resp.GetPassword() != "vaulted-password" {
		t.Fatalf("password = %q", resp.GetPassword())
	}
}

func TestIssueUpstreamCredentialRefusesForInactiveSession(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, UpstreamLogin: "svc", RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if err := f.store.CloseSession(opened.GetSessionId(), store.SessionClosed, "", 0, 0); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	if _, err := f.server.IssueUpstreamCredential(context.Background(), &auditproxyv1.IssueUpstreamCredentialRequest{
		SessionId: opened.GetSessionId(),
	}); err == nil {
		t.Fatal("a closed session was issued a credential")
	}

	if _, err := f.server.IssueUpstreamCredential(context.Background(), &auditproxyv1.IssueUpstreamCredentialRequest{
		SessionId: "no-such-session",
	}); err == nil {
		t.Fatal("an unknown session was issued a credential")
	}
}

func TestIssueUpstreamCredentialWithoutConfiguration(t *testing.T) {
	f := newFixture(t)
	rule := f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})
	opened, err := f.server.OpenSession(context.Background(), &auditproxyv1.OpenSessionRequest{
		Client: &auditproxyv1.ClientInfo{NodeId: "node-a"}, Username: "alice",
		TargetId: f.target.ID, UpstreamLogin: "nobody", RuleId: rule.ID,
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	resp, err := f.server.IssueUpstreamCredential(context.Background(), &auditproxyv1.IssueUpstreamCredentialRequest{
		SessionId: opened.GetSessionId(),
	})
	if err != nil {
		t.Fatalf("IssueUpstreamCredential: %v", err)
	}
	if resp.GetKind() != auditproxyv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED {
		t.Fatalf("kind = %v, want unspecified when nothing is configured", resp.GetKind())
	}
	if resp.GetReason() == "" {
		t.Error("the response should explain that no credential is configured")
	}
}

// --------------------------------------------------------------------------
// Event reporting
// --------------------------------------------------------------------------

type collectingSink struct {
	mu     sync.Mutex
	events []*auditproxyv1.AuditEvent
	err    error
}

func (s *collectingSink) Publish(_ context.Context, events []*auditproxyv1.AuditEvent) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	return nil
}

type eventStream struct {
	auditproxyv1.AccessDecisionService_ReportEventsServer
	ctx      context.Context
	batches  []*auditproxyv1.AuditEventBatch
	index    int
	response *auditproxyv1.ReportEventsResponse
}

func (s *eventStream) Recv() (*auditproxyv1.AuditEventBatch, error) {
	if s.index >= len(s.batches) {
		return nil, errEOF
	}
	batch := s.batches[s.index]
	s.index++
	return batch, nil
}

func (s *eventStream) SendAndClose(resp *auditproxyv1.ReportEventsResponse) error {
	s.response = resp
	return nil
}
func (s *eventStream) Context() context.Context     { return s.ctx }
func (s *eventStream) SetHeader(metadata.MD) error  { return nil }
func (s *eventStream) SendHeader(metadata.MD) error { return nil }
func (s *eventStream) SetTrailer(metadata.MD)       {}

// errEOF ends the simulated client stream, which is how a real gRPC client
// signals it has finished sending.
var errEOF = io.EOF

func TestReportEventsForwardsToTheSink(t *testing.T) {
	f := newFixture(t)
	sink := &collectingSink{}
	f.server.SetEventSink(sink)

	stream := &eventStream{
		ctx: context.Background(),
		batches: []*auditproxyv1.AuditEventBatch{
			{NodeId: "node-a", Events: []*auditproxyv1.AuditEvent{
				{Id: "e1", EventType: "session.start"},
				{Id: "e2", EventType: "command"},
			}},
			{NodeId: "node-a", Events: []*auditproxyv1.AuditEvent{{Id: "e3", EventType: "session.end"}}},
		},
	}
	if err := f.server.ReportEvents(stream); err != nil {
		t.Fatalf("ReportEvents: %v", err)
	}
	if stream.response.GetAccepted() != 3 {
		t.Fatalf("accepted = %d, want 3", stream.response.GetAccepted())
	}
	if len(sink.events) != 3 {
		t.Fatalf("the sink received %d events", len(sink.events))
	}
}

func TestReportEventsWithoutASinkDoesNotClaimDelivery(t *testing.T) {
	f := newFixture(t)
	stream := &eventStream{
		ctx: context.Background(),
		batches: []*auditproxyv1.AuditEventBatch{
			{Events: []*auditproxyv1.AuditEvent{{Id: "e1"}}},
		},
	}
	if err := f.server.ReportEvents(stream); err != nil {
		t.Fatalf("ReportEvents: %v", err)
	}
	if stream.response.GetAccepted() != 0 {
		t.Fatal("with nowhere to put them, events must not be reported as accepted; the sender would drop them")
	}
}

func TestReportEventsPropagatesSinkFailure(t *testing.T) {
	f := newFixture(t)
	f.server.SetEventSink(&collectingSink{err: errors.New("sink is down")})
	stream := &eventStream{
		ctx: context.Background(),
		batches: []*auditproxyv1.AuditEventBatch{
			{Events: []*auditproxyv1.AuditEvent{{Id: "e1"}}},
		},
	}
	if err := f.server.ReportEvents(stream); err == nil {
		t.Fatal("a sink failure should be reported so the sender keeps the events spooled")
	}
}
