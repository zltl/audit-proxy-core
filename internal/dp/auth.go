package dp

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// errAuthFailed is what every rejection returns. SSH surfaces the error text to
// nobody useful, but keeping one value makes it obvious in review that no code
// path leaks a distinguishing reason to the client.
var errAuthFailed = errors.New("authentication failed")

// authSession carries state between the authentication callbacks of one
// connection. golang.org/x/crypto/ssh calls them independently, so the partial
// result of a first factor has to be held somewhere until the second arrives.
type authSession struct {
	mu sync.Mutex
	// stateToken is the decision point's handle on a half-finished login.
	stateToken string
	username   string
	roles      []string
	// completed marks that the decision point granted full authentication.
	completed bool
}

// authState indexes in-flight authentication by SSH session id. Entries are
// removed when the handshake finishes, successfully or not.
type authStateTable struct {
	mu       sync.Mutex
	sessions map[string]*authSession
}

func newAuthStateTable() *authStateTable {
	return &authStateTable{sessions: make(map[string]*authSession)}
}

func (t *authStateTable) get(sessionID []byte) *authSession {
	key := string(sessionID)
	t.mu.Lock()
	defer t.mu.Unlock()
	state, ok := t.sessions[key]
	if !ok {
		state = &authSession{}
		t.sessions[key] = state
	}
	return state
}

func (t *authStateTable) release(sessionID []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, string(sessionID))
}

// clientInfo describes the connecting peer for the decision point.
func clientInfo(conn ssh.ConnMetadata, nodeID string) *sshproxyv1.ClientInfo {
	host, portText, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	port := 0
	if portText != "" {
		port = atoi(portText)
	}
	return &sshproxyv1.ClientInfo{
		SourceIp:      host,
		SourcePort:    int32(port),
		ClientVersion: string(conn.ClientVersion()),
		NodeId:        nodeID,
		ConnectionId:  base64.RawURLEncoding.EncodeToString(conn.SessionID()),
	}
}

// serverConfig builds the SSH server configuration for one connection.
func (s *Server) serverConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{
		ServerVersion: s.config.ServerVersion,
		// The default of six leaves room for a client to offer several keys
		// before falling back to a password, without allowing guessing.
		MaxAuthTries:                6,
		PasswordCallback:            s.passwordCallback,
		PublicKeyCallback:           s.publicKeyCallback,
		VerifiedPublicKeyCallback:   s.verifiedPublicKeyCallback,
		KeyboardInteractiveCallback: s.keyboardInteractiveCallback,
		AuthLogCallback:             s.authLogCallback,
		BannerCallback:              s.bannerCallback,
	}
	for _, signer := range s.hostSigners {
		config.AddHostKey(signer)
	}
	return config
}

func (s *Server) bannerCallback(ssh.ConnMetadata) string {
	if s.config.Banner == "" {
		return ""
	}
	return s.config.Banner + "\r\n"
}

func (s *Server) authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	if method != "none" {
		s.metrics.AuthAttempts.Add(1)
		if err != nil {
			s.metrics.AuthFailures.Add(1)
		}
	}
	if err == nil {
		log.Printf("dp: %s authenticated via %s from %s", conn.User(), method, conn.RemoteAddr())
		return
	}
	if method == "none" {
		// Clients always try "none" first to discover available methods; that
		// is not a failed attempt worth logging.
		return
	}
	log.Printf("dp: %s failed %s from %s", conn.User(), method, conn.RemoteAddr())
}

// passwordCallback runs the first factor.
func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.AuthTimeout)
	defer cancel()

	resp, err := s.pdp.Authenticate(ctx, &sshproxyv1.AuthenticateRequest{
		Client:   clientInfo(conn, s.config.NodeID),
		Username: principalOf(conn),
		Method:   sshproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: string(password),
	})
	if err != nil {
		log.Printf("dp: password authentication for %s could not be checked: %v", principalOf(conn), err)
		return nil, errAuthFailed
	}
	return s.applyAuthResult(conn, resp)
}

// publicKeyCallback runs before the client has proven it holds the private key.
//
// x/crypto/ssh calls this for an offered key during method discovery, so a
// decision made here would be based on an unproven claim. It therefore only
// checks that the key could be usable and defers the real decision to
// verifiedPublicKeyCallback.
func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return &ssh.Permissions{
		Extensions: map[string]string{
			"pubkey-fp": ssh.FingerprintSHA256(key),
		},
	}, nil
}

// verifiedPublicKeyCallback runs once the client has proven possession.
func (s *Server) verifiedPublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey, _ *ssh.Permissions, _ string) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.AuthTimeout)
	defer cancel()

	method := sshproxyv1.AuthMethod_AUTH_METHOD_PUBLIC_KEY
	fingerprint := ssh.FingerprintSHA256(key)
	if cert, ok := key.(*ssh.Certificate); ok {
		method = sshproxyv1.AuthMethod_AUTH_METHOD_CERTIFICATE
		fingerprint = ssh.FingerprintSHA256(cert.Key)
	}

	resp, err := s.pdp.Authenticate(ctx, &sshproxyv1.AuthenticateRequest{
		Client:               clientInfo(conn, s.config.NodeID),
		Username:             principalOf(conn),
		Method:               method,
		PublicKey:            base64.StdEncoding.EncodeToString(key.Marshal()),
		PublicKeyFingerprint: fingerprint,
		SignatureVerified:    true,
	})
	if err != nil {
		log.Printf("dp: public key authentication for %s could not be checked: %v", principalOf(conn), err)
		return nil, errAuthFailed
	}
	return s.applyAuthResult(conn, resp)
}

// keyboardInteractiveCallback drives the second factor.
func (s *Server) keyboardInteractiveCallback(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	state := s.authState.get(conn.SessionID())
	state.mu.Lock()
	token := state.stateToken
	state.mu.Unlock()

	if token == "" {
		// Reaching the second factor without having passed the first means the
		// client asked for keyboard-interactive on its own. There is nothing to
		// continue, and prompting anyway would turn this into a second password
		// channel that bypasses the first factor's rate limiting.
		return nil, errAuthFailed
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.config.AuthTimeout)
	defer cancel()

	for attempt := 0; attempt < 3; attempt++ {
		answers, err := challenge("", "Two-factor authentication", []string{"Verification code: "}, []bool{false})
		if err != nil {
			return nil, errAuthFailed
		}
		resp, err := s.pdp.Authenticate(ctx, &sshproxyv1.AuthenticateRequest{
			Client:     clientInfo(conn, s.config.NodeID),
			Username:   principalOf(conn),
			Method:     sshproxyv1.AuthMethod_AUTH_METHOD_KEYBOARD_INTERACTIVE,
			StateToken: token,
			Responses:  answers,
		})
		if err != nil {
			log.Printf("dp: second factor for %s could not be checked: %v", principalOf(conn), err)
			return nil, errAuthFailed
		}
		if resp.GetResult() == sshproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
			return s.applyAuthResult(conn, resp)
		}
		// The decision point re-issues state with the attempt counted; when it
		// stops doing so, no retries remain.
		if next := resp.GetStateToken(); next != "" {
			token = next
			state.mu.Lock()
			state.stateToken = next
			state.mu.Unlock()
			continue
		}
		return nil, errAuthFailed
	}
	return nil, errAuthFailed
}

// applyAuthResult turns a decision-point answer into an SSH outcome.
func (s *Server) applyAuthResult(conn ssh.ConnMetadata, resp *sshproxyv1.AuthenticateResponse) (*ssh.Permissions, error) {
	state := s.authState.get(conn.SessionID())

	switch resp.GetResult() {
	case sshproxyv1.AuthResult_AUTH_RESULT_SUCCESS:
		state.mu.Lock()
		state.username = resp.GetUsername()
		state.roles = resp.GetRoles()
		state.completed = true
		state.mu.Unlock()
		return &ssh.Permissions{
			Extensions: map[string]string{
				"username": resp.GetUsername(),
				"roles":    joinRoles(resp.GetRoles()),
			},
		}, nil

	case sshproxyv1.AuthResult_AUTH_RESULT_PARTIAL:
		state.mu.Lock()
		state.stateToken = resp.GetStateToken()
		state.username = resp.GetUsername()
		state.mu.Unlock()
		// PartialSuccessError tells the client the factor was accepted and
		// names what to try next, which is what makes password-then-code work
		// with an unmodified OpenSSH client.
		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.keyboardInteractiveCallback,
			},
		}

	default:
		return nil, errAuthFailed
	}
}

func joinRoles(roles []string) string {
	out := ""
	for i, role := range roles {
		if i > 0 {
			out += ","
		}
		out += role
	}
	return out
}

func splitRoles(raw string) []string {
	if raw == "" {
		return nil
	}
	var roles []string
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == ',' {
			if i > start {
				roles = append(roles, raw[start:i])
			}
			start = i + 1
		}
	}
	return roles
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// principalOf extracts the identity to authenticate from the SSH username,
// which also carries the destination.
func principalOf(conn ssh.ConnMetadata) string {
	return parseLoginSpec(conn.User()).Principal
}
