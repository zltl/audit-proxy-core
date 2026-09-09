package dp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	auditproxyv1 "github.com/zltl/audit-proxy-core/api/proto/auditproxy/v1"
)

// upstreamDialer connects to a target on behalf of a session.
type upstreamDialer struct {
	proxy *Server
}

// upstreamTarget describes where and as whom to connect.
type upstreamTarget struct {
	SessionID string
	TargetID  string
	Host      string
	Port      int
	Login     string
	Username  string
}

func (t upstreamTarget) address() string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(t.Host, itoa(port))
}

// dial establishes the upstream SSH connection.
//
// The host key is checked against the trust store before the connection is
// used. Without that, everything downstream — the recording, the command log,
// the transfer audit — would be a faithful record of a conversation with
// something that may not be the intended host.
func (d *upstreamDialer) dial(ctx context.Context, target upstreamTarget) (*ssh.Client, error) {
	// An ephemeral key pair is generated per session so a certificate can be
	// issued against it. The private half never leaves this process, so the
	// signing service never holds a credential that could be replayed.
	publicKey, ephemeral, err := generateEphemeralKey()
	if err != nil {
		return nil, err
	}

	credential, err := d.proxy.pdp.IssueUpstreamCredential(ctx, &auditproxyv1.IssueUpstreamCredentialRequest{
		SessionId:     target.SessionID,
		TargetId:      target.TargetID,
		UpstreamLogin: target.Login,
		Username:      target.Username,
		PublicKey:     publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("dp: obtain upstream credential: %w", err)
	}

	authMethods, err := buildAuthMethods(credential, ephemeral)
	if err != nil {
		return nil, err
	}

	clientConfig := &ssh.ClientConfig{
		User:            target.Login,
		Auth:            authMethods,
		Timeout:         d.proxy.config.UpstreamDialTimeout,
		HostKeyCallback: d.hostKeyCallback(ctx, target),
	}

	dialer := net.Dialer{Timeout: d.proxy.config.UpstreamDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target.address())
	if err != nil {
		return nil, fmt.Errorf("dp: connect to %s: %w", target.address(), err)
	}
	// The handshake gets its own deadline so a target that accepts a TCP
	// connection and then says nothing cannot hold a slot open indefinitely.
	_ = conn.SetDeadline(time.Now().Add(d.proxy.config.UpstreamDialTimeout))

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target.address(), clientConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dp: ssh handshake with %s: %w", target.address(), err)
	}
	_ = conn.SetDeadline(time.Time{})

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// hostKeyCallback asks the decision point about the key the upstream presented.
func (d *upstreamDialer) hostKeyCallback(ctx context.Context, target upstreamTarget) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		req := &auditproxyv1.ResolveHostKeyRequest{
			TargetId:    target.TargetID,
			TargetHost:  target.Host,
			TargetPort:  int32(target.Port),
			Algorithm:   key.Type(),
			PublicKey:   base64.StdEncoding.EncodeToString(key.Marshal()),
			Fingerprint: ssh.FingerprintSHA256(key),
		}
		if cert, ok := key.(*ssh.Certificate); ok && cert.SignatureKey != nil {
			req.IsCertificate = true
			req.CaFingerprint = ssh.FingerprintSHA256(cert.SignatureKey)
			// A pinned entry records the certified key rather than the
			// certificate blob, so that is what is reported for matching.
			req.Fingerprint = ssh.FingerprintSHA256(cert.Key)
			req.Algorithm = cert.Key.Type()
		}

		resp, err := d.proxy.pdp.ResolveHostKey(ctx, req)
		if err != nil {
			return fmt.Errorf("dp: host key could not be verified: %w", err)
		}
		if !resp.GetProceed() {
			d.proxy.metrics.HostKeysRefused.Add(1)
			return fmt.Errorf("dp: refusing %s: %s", target.address(), resp.GetReason())
		}
		return nil
	}
}

// buildAuthMethods turns an issued credential into SSH authentication methods.
func buildAuthMethods(cred *auditproxyv1.IssueUpstreamCredentialResponse, ephemeral ssh.Signer) ([]ssh.AuthMethod, error) {
	switch cred.GetKind() {
	case auditproxyv1.CredentialKind_CREDENTIAL_KIND_PASSWORD:
		return []ssh.AuthMethod{ssh.Password(cred.GetPassword())}, nil

	case auditproxyv1.CredentialKind_CREDENTIAL_KIND_PRIVATE_KEY:
		signer, err := ssh.ParsePrivateKey([]byte(cred.GetPrivateKey()))
		if err != nil {
			return nil, fmt.Errorf("dp: parse upstream private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	case auditproxyv1.CredentialKind_CREDENTIAL_KIND_CERTIFICATE:
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cred.GetCertificate()))
		if err != nil {
			return nil, fmt.Errorf("dp: parse issued certificate: %w", err)
		}
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("dp: the decision point returned a key, not a certificate")
		}
		certSigner, err := ssh.NewCertSigner(cert, ephemeral)
		if err != nil {
			return nil, fmt.Errorf("dp: build certificate signer: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(certSigner)}, nil

	case auditproxyv1.CredentialKind_CREDENTIAL_KIND_AGENT:
		return nil, fmt.Errorf("dp: agent-based upstream authentication requires agent forwarding, which this session does not have")

	default:
		reason := cred.GetReason()
		if reason == "" {
			reason = "no upstream credential was issued"
		}
		return nil, fmt.Errorf("dp: %s", reason)
	}
}

// generateEphemeralKey returns an Ed25519 key pair for one session.
func generateEphemeralKey() (authorizedKey string, signer ssh.Signer, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("dp: generate ephemeral key: %w", err)
	}
	signer, err = ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", nil, fmt.Errorf("dp: build ephemeral signer: %w", err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), signer, nil
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
