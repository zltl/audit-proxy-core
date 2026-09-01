package pdp

import (
	"context"
	"errors"
	"log"
	"path"
	"strings"
	"time"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// ResolveHostKey checks a host key presented by an upstream against the trust
// store.
//
// This is the check that makes a recorded session mean anything: without it the
// proxy cannot tell the intended host from something interposed between them,
// and would faithfully record a conversation with an impostor.
func (s *Server) ResolveHostKey(_ context.Context, req *sshproxyv1.ResolveHostKeyRequest) (*sshproxyv1.ResolveHostKeyResponse, error) {
	fingerprint := strings.TrimSpace(req.GetFingerprint())
	if fingerprint == "" {
		return rejectHostKey("no host key fingerprint was supplied"), nil
	}

	// A certificate signed by a trusted authority is accepted without pinning
	// the individual key, which is how a fleet rotates host keys.
	if req.GetIsCertificate() {
		trusted, err := s.hostCertificateTrusted(req)
		if err != nil {
			return nil, status(err, "check host certificate authority")
		}
		if trusted {
			return &sshproxyv1.ResolveHostKeyResponse{
				Verdict: sshproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_TRUSTED,
				Reason:  "signed by a trusted host certificate authority",
				Proceed: true,
			}, nil
		}
	}

	targetID := strings.TrimSpace(req.GetTargetId())
	if targetID == "" {
		target, err := s.store.FindTargetByAddress(req.GetTargetHost(), int(req.GetTargetPort()))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return rejectHostKey("this host is not a registered target"), nil
			}
			return nil, status(err, "resolve target for host key")
		}
		targetID = target.ID
	}

	keys, err := s.store.ListHostKeys(targetID)
	if err != nil {
		return nil, status(err, "list host keys")
	}
	for _, key := range keys {
		if !strings.EqualFold(key.Fingerprint, fingerprint) {
			continue
		}
		switch key.Status {
		case store.HostKeyTrusted:
			return &sshproxyv1.ResolveHostKeyResponse{
				Verdict: sshproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_TRUSTED,
				Reason:  "host key is pinned",
				Proceed: true,
			}, nil
		case store.HostKeyRevoked:
			return rejectHostKey("this host key has been revoked"), nil
		default:
			// Already recorded and still awaiting a decision.
			return &sshproxyv1.ResolveHostKeyResponse{
				Verdict: sshproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_PENDING,
				Reason:  "host key is awaiting operator approval",
				Proceed: s.config.TrustOnFirstUse,
			}, nil
		}
	}

	// The key is unknown. It is recorded either way so an operator can see what
	// was presented, but whether the connection continues is the deployment's
	// choice rather than this code's.
	if _, err := s.store.PutHostKey(store.HostKey{
		TargetID:    targetID,
		Algorithm:   req.GetAlgorithm(),
		PublicKey:   req.GetPublicKey(),
		Fingerprint: fingerprint,
		Status:      store.HostKeyPending,
		Source:      store.HostKeyTOFU,
		Comment:     "first seen at " + s.now().Format(time.RFC3339),
	}); err != nil {
		log.Printf("pdp: record first-contact host key for %s: %v", targetID, err)
	}

	if len(keys) > 0 && !s.config.TrustOnFirstUse {
		// A target that already has pinned keys presenting a different one is
		// the exact shape of an interception, so it is called out as such.
		return rejectHostKey("host key does not match any key pinned for this target"), nil
	}
	return &sshproxyv1.ResolveHostKeyResponse{
		Verdict: sshproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_PENDING,
		Reason:  "host key recorded on first contact and is awaiting approval",
		Proceed: s.config.TrustOnFirstUse,
	}, nil
}

func rejectHostKey(reason string) *sshproxyv1.ResolveHostKeyResponse {
	return &sshproxyv1.ResolveHostKeyResponse{
		Verdict: sshproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_REJECTED,
		Reason:  reason,
		Proceed: false,
	}
}

func (s *Server) hostCertificateTrusted(req *sshproxyv1.ResolveHostKeyRequest) (bool, error) {
	caFingerprint := strings.TrimSpace(req.GetCaFingerprint())
	if caFingerprint == "" {
		return false, nil
	}
	authorities, err := s.store.ListHostCAs()
	if err != nil {
		return false, err
	}
	host := strings.ToLower(strings.TrimSpace(req.GetTargetHost()))
	for _, ca := range authorities {
		if !strings.EqualFold(ca.Fingerprint, caFingerprint) {
			continue
		}
		if len(ca.HostPatterns) == 0 {
			return true, nil
		}
		for _, pattern := range ca.HostPatterns {
			if ok, err := path.Match(strings.ToLower(pattern), host); err == nil && ok {
				return true, nil
			}
		}
		// The authority is trusted, but not for this hostname. Accepting anyway
		// would let a CA scoped to one environment vouch for another.
		return false, nil
	}
	return false, nil
}

// --------------------------------------------------------------------------
// Upstream credentials
// --------------------------------------------------------------------------

// upstreamCertificateTTL bounds a certificate minted for one session. It is
// short because the certificate is only needed for the moment of connecting.
const upstreamCertificateTTL = 5 * time.Minute

// IssueUpstreamCredential returns what the proxy needs to authenticate to the
// upstream host for one session.
//
// Stored material is decrypted here and handed over for immediate use; the data
// plane never holds the key that would let it decrypt anything else, and never
// writes what it receives.
func (s *Server) IssueUpstreamCredential(_ context.Context, req *sshproxyv1.IssueUpstreamCredentialRequest) (*sshproxyv1.IssueUpstreamCredentialResponse, error) {
	session, err := s.store.GetSession(req.GetSessionId())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errors.New("pdp: unknown session")
		}
		return nil, status(err, "load session")
	}
	if session.Status != store.SessionActive {
		return nil, errors.New("pdp: session is not active")
	}
	// The credential is issued for the account the session was authorized for,
	// not for whatever the caller asks now, so a compromised data plane cannot
	// escalate by requesting a different account.
	login := session.UpstreamLogin
	if login == "" {
		login = strings.TrimSpace(req.GetUpstreamLogin())
	}

	target, err := s.store.GetTargetByID(session.TargetID)
	if err != nil {
		return nil, status(err, "load target")
	}
	credentials, err := s.store.CredentialsForTarget(target)
	if err != nil {
		return nil, status(err, "load credentials")
	}

	for _, cred := range credentials {
		if !strings.EqualFold(cred.Login, login) {
			continue
		}
		return s.materialiseCredential(cred, login, req.GetPublicKey())
	}

	return &sshproxyv1.IssueUpstreamCredentialResponse{
		Kind:   sshproxyv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED,
		Reason: "no credential is configured for " + login + " on " + target.Name,
	}, nil
}

func (s *Server) materialiseCredential(cred store.Credential, login, publicKey string) (*sshproxyv1.IssueUpstreamCredentialResponse, error) {
	switch cred.Kind {
	case store.CredentialCACert:
		if s.signer == nil {
			return nil, errors.New("pdp: no certificate signer is configured")
		}
		if strings.TrimSpace(publicKey) == "" {
			return nil, errors.New("pdp: a public key is required to issue a certificate")
		}
		certificate, expiresAt, err := s.signer.SignUpstreamCertificate(
			publicKey, []string{login}, upstreamCertificateTTL)
		if err != nil {
			return nil, status(err, "sign upstream certificate")
		}
		return &sshproxyv1.IssueUpstreamCredentialResponse{
			Kind:        sshproxyv1.CredentialKind_CREDENTIAL_KIND_CERTIFICATE,
			Certificate: certificate,
			ExpiresAt:   timestamp(expiresAt),
		}, nil

	case store.CredentialPassword:
		secret, err := s.store.GetSecretString(cred.SecretRef)
		if err != nil {
			return nil, status(err, "decrypt upstream password")
		}
		return &sshproxyv1.IssueUpstreamCredentialResponse{
			Kind:     sshproxyv1.CredentialKind_CREDENTIAL_KIND_PASSWORD,
			Password: secret,
		}, nil

	case store.CredentialPrivateKey:
		secret, err := s.store.GetSecretString(cred.SecretRef)
		if err != nil {
			return nil, status(err, "decrypt upstream private key")
		}
		return &sshproxyv1.IssueUpstreamCredentialResponse{
			Kind:       sshproxyv1.CredentialKind_CREDENTIAL_KIND_PRIVATE_KEY,
			PrivateKey: secret,
		}, nil

	case store.CredentialAgent:
		return &sshproxyv1.IssueUpstreamCredentialResponse{
			Kind:   sshproxyv1.CredentialKind_CREDENTIAL_KIND_AGENT,
			Reason: "forward the client's agent to authenticate",
		}, nil

	default:
		return nil, errors.New("pdp: unsupported credential kind " + string(cred.Kind))
	}
}
