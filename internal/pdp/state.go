// Package pdp implements the policy decision point the SSH data plane asks
// before it lets anything happen.
//
// The data plane holds sockets and moves bytes. Everything that could grant or
// widen access is decided here, against the database, at the moment it is
// asked. That split is what lets a revocation take effect on the next decision
// instead of the next configuration reload, and it keeps credential material
// out of the process that talks to untrusted clients.
package pdp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// authStage records where a multi-round authentication exchange has got to.
type authStage string

const (
	// stageAwaitMFA means the first factor succeeded and a second is required.
	stageAwaitMFA authStage = "await_mfa"
)

// authState is the content of a state token. Multi-round authentication needs
// continuity between calls, but keeping that continuity in memory would tie a
// connection to one decision-point instance and lose it on restart. Signing the
// state and handing it back to the caller keeps the service stateless.
type authState struct {
	Username  string    `json:"u"`
	Stage     authStage `json:"s"`
	ExpiresAt int64     `json:"e"`
	// Attempts bounds how many codes may be tried against one accepted password,
	// so a valid first factor does not become an unlimited oracle for the second.
	Attempts int `json:"a"`
}

var (
	errStateInvalid = errors.New("pdp: authentication state is not valid")
	errStateExpired = errors.New("pdp: authentication state has expired")
)

// stateTokenTTL bounds how long a half-finished login may be resumed.
const stateTokenTTL = 3 * time.Minute

// maxMFAAttempts is how many second-factor codes one accepted password buys.
const maxMFAAttempts = 5

// signState renders and authenticates an auth state.
func signState(secret []byte, state authState) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("pdp: encode auth state: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("pdp-auth-state\x00"))
	mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + signature, nil
}

// parseState verifies and decodes a state token.
func parseState(secret []byte, token string, now time.Time) (authState, error) {
	encoded, signature, found := cut(token, '.')
	if !found {
		return authState{}, errStateInvalid
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("pdp-auth-state\x00"))
	mac.Write([]byte(encoded))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return authState{}, errStateInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return authState{}, errStateInvalid
	}
	var state authState
	if err := json.Unmarshal(payload, &state); err != nil {
		return authState{}, errStateInvalid
	}
	if state.ExpiresAt <= 0 || now.Unix() > state.ExpiresAt {
		return authState{}, errStateExpired
	}
	return state, nil
}

func cut(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
