package pdp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/authn"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// Config tunes a Server.
type Config struct {
	// StateSecret signs multi-round authentication tokens. It must be the same
	// across decision-point instances so a login can finish on any of them.
	StateSecret []byte

	// TrustOnFirstUse records an unknown upstream host key and lets the
	// connection proceed. It is off by default: accepting an unverified host
	// key means the session being recorded may not be with the intended host.
	TrustOnFirstUse bool

	// MaxAuthFailures and LockoutWindow bound password guessing per account.
	MaxAuthFailures int
	LockoutWindow   time.Duration
	LockoutDuration time.Duration

	// NodeHeartbeatGrace is how long a session may go without a heartbeat
	// before it is treated as belonging to a crashed node.
	NodeHeartbeatGrace time.Duration
}

func (c Config) withDefaults() Config {
	if c.MaxAuthFailures == 0 {
		c.MaxAuthFailures = 5
	}
	if c.LockoutWindow == 0 {
		c.LockoutWindow = 15 * time.Minute
	}
	if c.LockoutDuration == 0 {
		c.LockoutDuration = 15 * time.Minute
	}
	if c.NodeHeartbeatGrace == 0 {
		c.NodeHeartbeatGrace = 2 * time.Minute
	}
	return c
}

// CertificateSigner mints short-lived certificates for the proxy to present to
// upstream hosts. It is an interface so the decision point does not depend on
// the CA implementation, and so a deployment can delegate signing elsewhere.
type CertificateSigner interface {
	SignUpstreamCertificate(publicKey string, principals []string, ttl time.Duration) (certificate string, expiresAt time.Time, err error)
}

// GrantChecker answers whether a time-limited grant currently covers a request,
// which is how just-in-time access participates in the decision.
type GrantChecker interface {
	HasGrant(username, target string) bool
}

// CommandApprover holds a command until a second person rules on it.
type CommandApprover interface {
	// Request registers a pending approval and returns its identifier.
	Request(ctx context.Context, sessionID, username, target, command, ruleID string) (string, error)
	// Await blocks until the request is decided or the context ends.
	Await(ctx context.Context, approvalID string) (approved bool, decidedBy string, err error)
}

// EventSink receives audit records reported by the data plane.
type EventSink interface {
	Publish(ctx context.Context, events []*sshproxyv1.AuditEvent) error
}

// Server implements the AccessDecisionService.
type Server struct {
	sshproxyv1.UnimplementedAccessDecisionServiceServer

	store  *store.Store
	config Config

	signer   CertificateSigner
	grants   GrantChecker
	approver CommandApprover
	sink     EventSink

	// failures tracks recent authentication failures per account.
	failuresMu sync.Mutex
	failures   map[string]*failureRecord

	// decoyHash is a real argon2id hash of a value nobody knows. Verifying a
	// password against it when the account does not exist makes the work done
	// for an unknown user comparable to that for a known one, so response time
	// does not reveal which usernames are real.
	decoyHash string

	now func() time.Time
}

type failureRecord struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// New builds a decision point over a store.
func New(st *store.Store, cfg Config) (*Server, error) {
	if st == nil {
		return nil, errors.New("pdp: a store is required")
	}
	cfg = cfg.withDefaults()
	if len(cfg.StateSecret) == 0 {
		return nil, errors.New("pdp: a state secret is required to sign multi-round authentication tokens")
	}
	decoy, err := newDecoyHash()
	if err != nil {
		return nil, err
	}
	return &Server{
		store:     st,
		config:    cfg,
		failures:  make(map[string]*failureRecord),
		decoyHash: decoy,
		now:       func() time.Time { return time.Now().UTC() },
	}, nil
}

// newDecoyHash produces an argon2id hash of random material, so that comparing
// against it costs the same as comparing against a real stored password.
func newDecoyHash() (string, error) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("pdp: generate decoy material: %w", err)
	}
	hash, err := authn.HashPassword(hex.EncodeToString(material[:]))
	if err != nil {
		return "", fmt.Errorf("pdp: build decoy hash: %w", err)
	}
	return hash, nil
}

// SetCertificateSigner attaches the signer used for upstream certificates.
func (s *Server) SetCertificateSigner(signer CertificateSigner) { s.signer = signer }

// SetGrantChecker attaches a just-in-time grant source.
func (s *Server) SetGrantChecker(checker GrantChecker) { s.grants = checker }

// SetCommandApprover attaches the approval workflow used by command policy.
func (s *Server) SetCommandApprover(approver CommandApprover) { s.approver = approver }

// SetEventSink attaches the destination for reported audit events.
func (s *Server) SetEventSink(sink EventSink) { s.sink = sink }

// SetClock overrides the time source, for tests.
func (s *Server) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// --------------------------------------------------------------------------
// Authenticate
// --------------------------------------------------------------------------

// Authenticate runs one step of the SSH authentication exchange.
func (s *Server) Authenticate(ctx context.Context, req *sshproxyv1.AuthenticateRequest) (*sshproxyv1.AuthenticateResponse, error) {
	username := strings.TrimSpace(req.GetUsername())
	if username == "" {
		return authFailure("username is required"), nil
	}

	if locked, until := s.isLockedOut(username); locked {
		return authFailure(fmt.Sprintf("account is temporarily locked until %s",
			until.Format(time.RFC3339))), nil
	}

	// A source network may be refused before any credential is examined, so a
	// blocked network cannot be used to probe which accounts exist.
	if allowed, _, err := s.store.CheckSourceIP(req.GetClient().GetSourceIp()); err != nil {
		return nil, status(err, "check source address")
	} else if !allowed {
		return authFailure("connections from this network are not permitted"), nil
	}

	switch req.GetMethod() {
	case sshproxyv1.AuthMethod_AUTH_METHOD_PASSWORD:
		return s.authenticatePassword(ctx, req)
	case sshproxyv1.AuthMethod_AUTH_METHOD_PUBLIC_KEY,
		sshproxyv1.AuthMethod_AUTH_METHOD_CERTIFICATE:
		return s.authenticatePublicKey(ctx, req)
	case sshproxyv1.AuthMethod_AUTH_METHOD_KEYBOARD_INTERACTIVE:
		return s.authenticateKeyboardInteractive(ctx, req)
	default:
		return authFailure("authentication method is not supported"), nil
	}
}

func (s *Server) authenticatePassword(_ context.Context, req *sshproxyv1.AuthenticateRequest) (*sshproxyv1.AuthenticateResponse, error) {
	username := strings.TrimSpace(req.GetUsername())
	user, err := s.store.GetUser(username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The same message and the same work are used for an unknown account
			// as for a wrong password, so neither timing nor wording reveals
			// which accounts exist.
			s.recordFailure(username)
			authn.VerifyPassword(req.GetPassword(), s.decoyHash)
			return authFailure("authentication failed"), nil
		}
		return nil, status(err, "load user")
	}

	if !user.Enabled() {
		s.recordFailure(username)
		return authFailure("authentication failed"), nil
	}
	if user.PasswordHash == "" || !authn.VerifyPassword(req.GetPassword(), user.PasswordHash) {
		s.recordFailure(username)
		return authFailure("authentication failed"), nil
	}
	s.clearFailures(username)

	return s.completeOrChallenge(user)
}

func (s *Server) authenticatePublicKey(_ context.Context, req *sshproxyv1.AuthenticateRequest) (*sshproxyv1.AuthenticateResponse, error) {
	// The data plane verifies the client's signature during the SSH handshake;
	// without that proof a fingerprint is only a claim, so the decision point
	// refuses rather than trusting the caller to have checked.
	if !req.GetSignatureVerified() {
		return authFailure("public key possession was not proven"), nil
	}
	fingerprint := strings.TrimSpace(req.GetPublicKeyFingerprint())
	if fingerprint == "" {
		return authFailure("public key fingerprint is required"), nil
	}

	key, user, err := s.store.FindPublicKey(fingerprint)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.recordFailure(req.GetUsername())
			return authFailure("authentication failed"), nil
		}
		return nil, status(err, "resolve public key")
	}
	if !strings.EqualFold(user.Username, strings.TrimSpace(req.GetUsername())) {
		// The key is known but belongs to somebody else. Accepting it would let
		// one user log in under another's name.
		s.recordFailure(req.GetUsername())
		return authFailure("authentication failed"), nil
	}
	if key.Expired(s.now()) {
		return authFailure("this public key has expired"), nil
	}
	if !user.Enabled() {
		return authFailure("authentication failed"), nil
	}

	s.clearFailures(user.Username)
	if err := s.store.TouchPublicKey(fingerprint, s.now()); err != nil {
		log.Printf("pdp: record public key use for %s: %v", user.Username, err)
	}
	return s.completeOrChallenge(user)
}

func (s *Server) authenticateKeyboardInteractive(_ context.Context, req *sshproxyv1.AuthenticateRequest) (*sshproxyv1.AuthenticateResponse, error) {
	state, err := parseState(s.config.StateSecret, req.GetStateToken(), s.now())
	if err != nil {
		return authFailure("this login attempt has expired; start again"), nil
	}
	if state.Stage != stageAwaitMFA {
		return authFailure("unexpected authentication step"), nil
	}
	if state.Attempts >= maxMFAAttempts {
		s.recordFailure(state.Username)
		return authFailure("too many incorrect codes"), nil
	}
	if len(req.GetResponses()) == 0 {
		return authFailure("a verification code is required"), nil
	}

	user, err := s.store.GetUser(state.Username)
	if err != nil {
		return authFailure("authentication failed"), nil
	}
	if !user.Enabled() || user.MFAType != store.MFATOTP || user.MFASecretRef == "" {
		return authFailure("authentication failed"), nil
	}

	secret, err := s.store.GetSecretString(user.MFASecretRef)
	if err != nil {
		return nil, status(err, "load MFA secret")
	}
	if !authn.ValidateTOTP(secret, req.GetResponses()[0], authn.DefaultTOTPConfig()) {
		// Re-issue the state with the attempt counted, so the client can retry a
		// bounded number of times without restarting from the password.
		state.Attempts++
		token, tokenErr := signState(s.config.StateSecret, state)
		if tokenErr != nil {
			return nil, status(tokenErr, "issue authentication state")
		}
		resp := authFailure("incorrect verification code")
		resp.StateToken = token
		return resp, nil
	}

	s.clearFailures(user.Username)
	return s.authSuccess(user)
}

// completeOrChallenge finishes authentication, or asks for a second factor when
// the account has one enrolled.
func (s *Server) completeOrChallenge(user store.User) (*sshproxyv1.AuthenticateResponse, error) {
	if user.MFAType != store.MFATOTP || user.MFASecretRef == "" || user.MFAPending {
		return s.authSuccess(user)
	}
	state := authState{
		Username:  user.Username,
		Stage:     stageAwaitMFA,
		ExpiresAt: s.now().Add(stateTokenTTL).Unix(),
	}
	token, err := signState(s.config.StateSecret, state)
	if err != nil {
		return nil, status(err, "issue authentication state")
	}
	return &sshproxyv1.AuthenticateResponse{
		Result:           sshproxyv1.AuthResult_AUTH_RESULT_PARTIAL,
		Username:         user.Username,
		RemainingMethods: []sshproxyv1.AuthMethod{sshproxyv1.AuthMethod_AUTH_METHOD_KEYBOARD_INTERACTIVE},
		Instruction:      "Two-factor authentication",
		Prompts:          []*sshproxyv1.AuthPrompt{{Prompt: "Verification code: ", Echo: false}},
		StateToken:       token,
	}, nil
}

func (s *Server) authSuccess(user store.User) (*sshproxyv1.AuthenticateResponse, error) {
	roles, err := s.store.RolesForUser(user.Username)
	if err != nil {
		return nil, status(err, "load roles")
	}
	if err := s.store.RecordLogin(user.Username, s.now()); err != nil {
		log.Printf("pdp: record login for %s: %v", user.Username, err)
	}
	return &sshproxyv1.AuthenticateResponse{
		Result:                 sshproxyv1.AuthResult_AUTH_RESULT_SUCCESS,
		Username:               user.Username,
		Roles:                  roles,
		PasswordChangeRequired: user.PasswordChangeRequired,
	}, nil
}

func authFailure(reason string) *sshproxyv1.AuthenticateResponse {
	return &sshproxyv1.AuthenticateResponse{
		Result: sshproxyv1.AuthResult_AUTH_RESULT_FAILURE,
		Reason: reason,
	}
}

// --------------------------------------------------------------------------
// Lockout
// --------------------------------------------------------------------------

func (s *Server) isLockedOut(username string) (bool, time.Time) {
	s.failuresMu.Lock()
	defer s.failuresMu.Unlock()
	record, ok := s.failures[strings.ToLower(username)]
	if !ok {
		return false, time.Time{}
	}
	now := s.now()
	if record.lockedUntil.After(now) {
		return true, record.lockedUntil
	}
	return false, time.Time{}
}

func (s *Server) recordFailure(username string) {
	key := strings.ToLower(strings.TrimSpace(username))
	if key == "" {
		return
	}
	now := s.now()
	s.failuresMu.Lock()
	defer s.failuresMu.Unlock()

	record, ok := s.failures[key]
	if !ok || now.Sub(record.windowStart) > s.config.LockoutWindow {
		s.failures[key] = &failureRecord{count: 1, windowStart: now}
		return
	}
	record.count++
	if record.count >= s.config.MaxAuthFailures {
		record.lockedUntil = now.Add(s.config.LockoutDuration)
		record.count = 0
		record.windowStart = now
	}
}

func (s *Server) clearFailures(username string) {
	s.failuresMu.Lock()
	defer s.failuresMu.Unlock()
	delete(s.failures, strings.ToLower(strings.TrimSpace(username)))
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

// status wraps an internal failure. The detail is kept for the operator's logs;
// what reaches the client is the generic wrapper, since a database error should
// not describe the schema to whoever is connecting.
func status(err error, action string) error {
	log.Printf("pdp: %s: %v", action, err)
	return fmt.Errorf("pdp: %s failed", action)
}

func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
