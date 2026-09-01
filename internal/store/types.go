// Package store owns the data-plane's authoritative state: identities, their
// credentials, the targets they may reach, the rules that decide whether a
// given connection is allowed, and the sessions currently in flight.
//
// Everything here lives in the database rather than in a configuration file so
// that a change takes effect without a reload, an operator action is auditable,
// and several proxy nodes see the same policy at the same time. A config file
// can still seed these tables (see the ini import), but it is no longer the
// source of truth.
package store

import (
	"strings"
	"time"
)

// UserStatus is the lifecycle state of an identity.
type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
	UserLocked   UserStatus = "locked"
)

// IdentitySource records where an identity came from, which decides whether
// this system owns the password or defers to an external provider.
type IdentitySource string

const (
	SourceLocal IdentitySource = "local"
	SourceLDAP  IdentitySource = "ldap"
	SourceOIDC  IdentitySource = "oidc"
	SourceSAML  IdentitySource = "saml"
)

// MFAType identifies the second factor bound to an identity.
type MFAType string

const (
	MFANone MFAType = "none"
	MFATOTP MFAType = "totp"
)

// User is a principal that can authenticate to the proxy. It covers both
// console operators and SSH users; what they may do is decided by role bindings
// and access rules, not by which table they live in.
type User struct {
	ID                     string
	Username               string
	DisplayName            string
	Email                  string
	Status                 UserStatus
	Source                 IdentitySource
	PasswordHash           string
	PasswordChangedAt      time.Time
	PasswordChangeRequired bool
	MFAType                MFAType
	// MFASecretRef points at a row in dp_secrets. The seed itself never sits in
	// this table in plaintext.
	MFASecretRef string
	MFAPending   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  time.Time
}

// Enabled reports whether the account may authenticate at all.
func (u User) Enabled() bool { return u.Status == UserActive }

// PublicKey is an SSH public key authorised for a user.
type PublicKey struct {
	ID          string
	UserID      string
	Fingerprint string
	Algorithm   string
	PublicKey   string
	Comment     string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	LastUsedAt  time.Time
}

// Expired reports whether the key may no longer be used.
func (k PublicKey) Expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt)
}

// SubjectKind distinguishes what a role binding or access rule is attached to.
type SubjectKind string

const (
	SubjectUser  SubjectKind = "user"
	SubjectRole  SubjectKind = "role"
	SubjectGroup SubjectKind = "group"
	SubjectAny   SubjectKind = "any"
)

// Role is a named bundle of privileges.
type Role struct {
	Name        string
	Description string
	Builtin     bool
	CreatedAt   time.Time
}

// RoleBinding grants a role to a user or group.
type RoleBinding struct {
	ID          string
	SubjectKind SubjectKind
	Subject     string
	Role        string
	CreatedAt   time.Time
}

// Target is an upstream host the proxy can connect to.
type Target struct {
	ID          string
	Name        string
	Host        string
	Port        int
	Group       string
	Tags        map[string]string
	OS          string
	Enabled     bool
	Maintenance bool
	Weight      int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Address renders the dial address for the target.
func (t Target) Address() string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return t.Host + ":" + itoa(port)
}

// HostKeyStatus is the trust state of a recorded upstream host key.
type HostKeyStatus string

const (
	// HostKeyTrusted keys are accepted.
	HostKeyTrusted HostKeyStatus = "trusted"
	// HostKeyPending keys were learned on first contact and are awaiting an
	// operator decision. Whether a pending key is accepted depends on the
	// deployment's trust-on-first-use setting.
	HostKeyPending HostKeyStatus = "pending"
	// HostKeyRevoked keys are refused outright, which is how a compromised or
	// rotated host key is retired.
	HostKeyRevoked HostKeyStatus = "revoked"
)

// HostKeySource records how a host key entered the trust store.
type HostKeySource string

const (
	HostKeyManual HostKeySource = "manual"
	HostKeyTOFU   HostKeySource = "tofu"
	HostKeyScan   HostKeySource = "scan"
)

// HostKey is a pinned upstream host key. Without these the proxy cannot tell a
// target apart from something impersonating it, which would make every session
// it records untrustworthy.
type HostKey struct {
	ID          string
	TargetID    string
	Algorithm   string
	PublicKey   string
	Fingerprint string
	Status      HostKeyStatus
	Source      HostKeySource
	FirstSeenAt time.Time
	TrustedAt   time.Time
	Comment     string
}

// HostCA is a certificate authority whose host certificates are accepted for
// matching hostnames, so that fleets can rotate host keys without repinning.
type HostCA struct {
	ID          string
	Name        string
	PublicKey   string
	Fingerprint string
	// HostPatterns are shell-style globs matched against the target host.
	HostPatterns []string
	CreatedAt    time.Time
}

// CredentialKind is how the proxy authenticates to an upstream host.
type CredentialKind string

const (
	// CredentialPassword is a vaulted password for the upstream account.
	CredentialPassword CredentialKind = "password"
	// CredentialPrivateKey is a vaulted private key.
	CredentialPrivateKey CredentialKind = "private_key"
	// CredentialCACert asks the SSH CA for a short-lived certificate at connect
	// time. Preferred: nothing long-lived is stored and expiry bounds exposure.
	CredentialCACert CredentialKind = "ca_cert"
	// CredentialAgent forwards the user's own agent to the upstream.
	CredentialAgent CredentialKind = "agent"
)

// Credential describes how to log in to a target as a particular account. The
// secret material lives in dp_secrets and is only ever decrypted inside the
// policy decision point.
type Credential struct {
	ID             string
	TargetID       string
	TargetSelector string
	Login          string
	Kind           CredentialKind
	SecretRef      string
	RotateAfter    time.Duration
	LastRotatedAt  time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NeedsRotation reports whether the credential is past its rotation interval.
func (c Credential) NeedsRotation(now time.Time) bool {
	if c.RotateAfter <= 0 {
		return false
	}
	if c.LastRotatedAt.IsZero() {
		return true
	}
	return now.After(c.LastRotatedAt.Add(c.RotateAfter))
}

// Effect is whether a rule permits or refuses.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// RecordPolicy is how much of a session is captured.
type RecordPolicy string

const (
	// RecordFull captures the full terminal stream plus commands and transfers.
	RecordFull RecordPolicy = "full"
	// RecordCommands captures command and transfer metadata but not the stream,
	// which is what regulated environments use when screen content is sensitive.
	RecordCommands RecordPolicy = "commands"
	RecordNone     RecordPolicy = "none"
)

// TimeWindow restricts when a rule applies, in the named IANA location.
type TimeWindow struct {
	// Days holds ISO weekday numbers, 1 (Monday) through 7 (Sunday). Empty means
	// every day.
	Days []int `json:"days,omitempty"`
	// Start and End are "HH:MM" in Location. A window whose End is before its
	// Start wraps past midnight.
	Start    string `json:"start"`
	End      string `json:"end"`
	Location string `json:"location,omitempty"`
}

// AccessRule decides whether a subject may open a session to a target, and
// under what constraints. Rules are evaluated in priority order; the first
// match wins, and an explicit deny at the same priority beats an allow.
type AccessRule struct {
	ID             string
	Name           string
	Priority       int
	Effect         Effect
	SubjectKind    SubjectKind
	Subject        string
	TargetSelector string
	// UpstreamLogins limits which upstream accounts may be assumed. Empty means
	// any account a matching credential provides.
	UpstreamLogins []string
	// Features and DeniedFeatures gate SSH capabilities such as port forwarding
	// or file transfer; DeniedFeatures wins on conflict.
	Features        FeatureSet
	DeniedFeatures  FeatureSet
	SourceCIDRs     []string
	TimeWindows     []TimeWindow
	MaxSessionTTL   time.Duration
	IdleTimeout     time.Duration
	MaxConcurrent   int
	RecordPolicy    RecordPolicy
	CommandPolicyID string
	// ApprovalRequired holds the session until a second person approves it.
	ApprovalRequired bool
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// CommandPolicy groups command rules so they can be attached to access rules.
type CommandPolicy struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CommandAction is what to do with a command that matches a rule.
type CommandAction string

const (
	CommandAllow   CommandAction = "allow"
	CommandDeny    CommandAction = "deny"
	CommandAudit   CommandAction = "audit"
	CommandApprove CommandAction = "approve"
	CommandRewrite CommandAction = "rewrite"
)

// CommandRule matches a command line and decides its fate.
type CommandRule struct {
	ID        string
	PolicyID  string
	Priority  int
	Pattern   string
	Action    CommandAction
	Rewrite   string
	Severity  string
	Message   string
	Enabled   bool
	CreatedAt time.Time
}

// IPRuleAction is the disposition for a client network.
type IPRuleAction string

const (
	IPAllow IPRuleAction = "allow"
	IPDeny  IPRuleAction = "deny"
)

// IPRule allows or denies client source networks before authentication.
type IPRule struct {
	ID        string
	CIDR      string
	Action    IPRuleAction
	Priority  int
	Comment   string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// SessionStatus is the lifecycle state of a proxied session.
type SessionStatus string

const (
	SessionPending    SessionStatus = "pending"
	SessionActive     SessionStatus = "active"
	SessionClosed     SessionStatus = "closed"
	SessionTerminated SessionStatus = "terminated"
)

// Session is a proxied SSH connection. It lives in the shared database rather
// than in one node's memory so that any node can list and terminate a session
// started on any other.
type Session struct {
	ID            string
	NodeID        string
	Username      string
	SourceIP      string
	ClientVersion string
	TargetID      string
	TargetHost    string
	TargetPort    int
	UpstreamLogin string
	Status        SessionStatus
	StartedAt     time.Time
	LastSeenAt    time.Time
	ClosedAt      time.Time
	BytesIn       int64
	BytesOut      int64
	RecordingRef  string
	// RevokeRequested is set by whichever node handled the operator's request;
	// the node owning the session notices it and disconnects.
	RevokeRequested bool
	RevokeReason    string
	TerminationInfo string
}

// Duration returns how long the session ran, or has been running.
func (s Session) Duration(now time.Time) time.Duration {
	if s.StartedAt.IsZero() {
		return 0
	}
	end := s.ClosedAt
	if end.IsZero() {
		end = now
	}
	return end.Sub(s.StartedAt)
}

// Secret is an envelope-encrypted blob. The plaintext is never stored and never
// leaves the process that holds the key-encryption key.
type Secret struct {
	ID         string
	Kind       string
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
	AAD        string
	Version    int
	CreatedAt  time.Time
	RotatedAt  time.Time
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

// normalizeSelector trims and lowercases a selector for consistent matching.
func normalizeSelector(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
