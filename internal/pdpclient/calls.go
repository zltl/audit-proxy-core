package pdpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// Authenticate forwards one authentication step.
//
// Authentication is never served from cache and never softened by the fail
// mode: admitting somebody whose credentials could not be checked is the one
// outcome that cannot be walked back.
func (c *Client) Authenticate(ctx context.Context, req *sshproxyv1.AuthenticateRequest) (*sshproxyv1.AuthenticateResponse, error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.api.Authenticate(callCtx, req)
	if err != nil {
		if unreachable(err) {
			c.markUnhealthy(err)
		}
		return nil, err
	}
	c.markHealthy()
	return resp, nil
}

// AuthorizeSession asks whether a session may be opened.
func (c *Client) AuthorizeSession(ctx context.Context, req *sshproxyv1.AuthorizeSessionRequest) (*sshproxyv1.AuthorizeSessionResponse, error) {
	key := sessionCacheKey(req)
	if cached, ok := c.cache.Get(key); ok {
		if resp, ok := cached.(*sshproxyv1.AuthorizeSessionResponse); ok {
			return resp, nil
		}
	}

	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.api.AuthorizeSession(callCtx, req)
	if err != nil {
		if !unreachable(err) {
			return nil, err
		}
		c.markUnhealthy(err)
		return c.sessionFallback(err)
	}
	c.markHealthy()
	// Only positive decisions are cached. Caching a refusal would keep somebody
	// locked out for the TTL after the grant that fixes it is added, and there
	// is no burst to absorb on the refusal path.
	if resp.GetAllowed() {
		c.cache.Put(key, resp)
	}
	return resp, nil
}

// sessionFallback applies the fail mode when the decision point is unreachable.
func (c *Client) sessionFallback(cause error) (*sshproxyv1.AuthorizeSessionResponse, error) {
	if c.config.FailMode == FailOpen {
		log.Printf("pdpclient: decision point unreachable (%v); admitting the session because fail_mode is open", cause)
		return &sshproxyv1.AuthorizeSessionResponse{
			Allowed: true,
			Reason:  "decision point unreachable; admitted under fail-open policy",
			Features: []string{
				"shell", "exec", "pty", "env",
			},
		}, nil
	}
	return &sshproxyv1.AuthorizeSessionResponse{
		Allowed: false,
		Reason:  "the access policy could not be consulted; refusing",
	}, nil
}

func sessionCacheKey(req *sshproxyv1.AuthorizeSessionRequest) string {
	var b strings.Builder
	b.WriteString("session\x00")
	b.WriteString(req.GetUsername())
	b.WriteString("\x00")
	b.WriteString(strings.Join(req.GetRoles(), ","))
	b.WriteString("\x00")
	b.WriteString(req.GetTarget())
	b.WriteString("\x00")
	b.WriteString(req.GetTargetHost())
	b.WriteString("\x00")
	b.WriteString(req.GetUpstreamLogin())
	b.WriteString("\x00")
	b.WriteString(req.GetClient().GetSourceIp())
	return b.String()
}

// AuthorizeChannel asks whether a channel or channel request may proceed.
func (c *Client) AuthorizeChannel(ctx context.Context, req *sshproxyv1.AuthorizeChannelRequest) (*sshproxyv1.AuthorizeChannelResponse, error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.api.AuthorizeChannel(callCtx, req)
	if err != nil {
		if !unreachable(err) {
			return nil, err
		}
		c.markUnhealthy(err)
		if c.config.FailMode == FailOpen {
			return &sshproxyv1.AuthorizeChannelResponse{
				Allowed: true,
				Reason:  "decision point unreachable; permitted under fail-open policy",
			}, nil
		}
		return &sshproxyv1.AuthorizeChannelResponse{
			Allowed: false,
			Reason:  "the access policy could not be consulted; refusing",
		}, nil
	}
	c.markHealthy()
	return resp, nil
}

// CommandDecisionFunc receives each stage of a command decision. Approval turns
// one request into two answers, so the caller is handed both rather than only
// the last.
type CommandDecisionFunc func(*sshproxyv1.AuthorizeCommandResponse)

// AuthorizeCommand screens a command, blocking while an approval is pending.
//
// It returns the final decision. onUpdate, if supplied, sees the intermediate
// pending message so the data plane can tell the user why their shell paused
// instead of leaving them staring at nothing.
func (c *Client) AuthorizeCommand(
	ctx context.Context,
	req *sshproxyv1.AuthorizeCommandRequest,
	onUpdate CommandDecisionFunc,
) (*sshproxyv1.AuthorizeCommandResponse, error) {
	// No per-call timeout here: an approval legitimately takes as long as the
	// approver does, and the caller's context already bounds the session.
	stream, err := c.api.AuthorizeCommand(ctx, req)
	if err != nil {
		if !unreachable(err) {
			return nil, err
		}
		c.markUnhealthy(err)
		return c.commandFallback(), nil
	}

	var last *sshproxyv1.AuthorizeCommandResponse
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if !unreachable(err) {
				return nil, err
			}
			c.markUnhealthy(err)
			if last != nil && last.GetDecision() != sshproxyv1.CommandDecision_COMMAND_DECISION_PENDING_APPROVAL {
				return last, nil
			}
			return c.commandFallback(), nil
		}
		c.markHealthy()
		last = resp
		if onUpdate != nil {
			onUpdate(resp)
		}
		if resp.GetDecision() != sshproxyv1.CommandDecision_COMMAND_DECISION_PENDING_APPROVAL {
			// A terminal decision arrived; nothing further is expected.
			break
		}
	}
	if last == nil {
		return c.commandFallback(), nil
	}
	return last, nil
}

func (c *Client) commandFallback() *sshproxyv1.AuthorizeCommandResponse {
	if c.config.FailMode == FailOpen {
		return &sshproxyv1.AuthorizeCommandResponse{
			Decision: sshproxyv1.CommandDecision_COMMAND_DECISION_ALLOW,
			Reason:   "command policy could not be consulted; allowed under fail-open policy",
		}
	}
	return &sshproxyv1.AuthorizeCommandResponse{
		Decision: sshproxyv1.CommandDecision_COMMAND_DECISION_DENY,
		Reason:   "command policy could not be consulted; refusing",
	}
}

// ResolveHostKey checks an upstream host key against the trust store.
//
// The fail mode does not apply here in either direction: an unverifiable host
// key is refused even under fail-open, because proceeding would mean recording
// a session with something that may not be the intended host, which defeats the
// purpose of the proxy rather than merely inconveniencing a user.
func (c *Client) ResolveHostKey(ctx context.Context, req *sshproxyv1.ResolveHostKeyRequest) (*sshproxyv1.ResolveHostKeyResponse, error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.api.ResolveHostKey(callCtx, req)
	if err != nil {
		if unreachable(err) {
			c.markUnhealthy(err)
			return &sshproxyv1.ResolveHostKeyResponse{
				Verdict: sshproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_REJECTED,
				Reason:  "the host key trust store could not be consulted",
				Proceed: false,
			}, nil
		}
		return nil, err
	}
	c.markHealthy()
	return resp, nil
}

// IssueUpstreamCredential fetches the material for connecting to the upstream.
func (c *Client) IssueUpstreamCredential(ctx context.Context, req *sshproxyv1.IssueUpstreamCredentialRequest) (*sshproxyv1.IssueUpstreamCredentialResponse, error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.api.IssueUpstreamCredential(callCtx, req)
	if err != nil {
		if unreachable(err) {
			c.markUnhealthy(err)
		}
		// There is no fallback: the material only exists on the other side.
		return nil, err
	}
	c.markHealthy()
	return resp, nil
}

// OpenSession registers a session.
func (c *Client) OpenSession(ctx context.Context, req *sshproxyv1.OpenSessionRequest) (*sshproxyv1.OpenSessionResponse, error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.api.OpenSession(callCtx, req)
	if err != nil {
		if !unreachable(err) {
			return nil, err
		}
		c.markUnhealthy(err)
		if c.config.FailMode == FailOpen {
			// Without a shared record the session cannot be listed or killed
			// remotely, which is called out so it is visible in the log rather
			// than discovered when somebody tries to terminate it.
			log.Printf("pdpclient: session registry unreachable; proceeding without a shared session record")
			return &sshproxyv1.OpenSessionResponse{
				SessionId: "local-" + time.Now().UTC().Format("20060102150405.000000000"),
				Allowed:   true,
				Reason:    "session registry unreachable; not recorded centrally",
			}, nil
		}
		return &sshproxyv1.OpenSessionResponse{
			Allowed: false,
			Reason:  "the session registry could not be reached; refusing",
		}, nil
	}
	c.markHealthy()
	return resp, nil
}

// HeartbeatSession refreshes a session and reports a pending revocation.
func (c *Client) HeartbeatSession(ctx context.Context, sessionID string, bytesIn, bytesOut int64) (revoked bool, reason string, err error) {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	resp, err := c.api.HeartbeatSession(callCtx, &sshproxyv1.HeartbeatSessionRequest{
		SessionId: sessionID, BytesIn: bytesIn, BytesOut: bytesOut,
	})
	if err != nil {
		if unreachable(err) {
			c.markUnhealthy(err)
			// A missed heartbeat is not a reason to cut an established session:
			// the user is already inside, the recording is already running, and
			// dropping them would turn a control-plane blip into an outage.
			return false, "", nil
		}
		return false, "", err
	}
	c.markHealthy()
	if resp.GetRevoked() {
		c.cache.Clear()
	}
	return resp.GetRevoked(), resp.GetReason(), nil
}

// CloseSession records the end of a session.
func (c *Client) CloseSession(ctx context.Context, req *sshproxyv1.CloseSessionRequest) error {
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	if _, err := c.api.CloseSession(callCtx, req); err != nil {
		if unreachable(err) {
			c.markUnhealthy(err)
			return nil
		}
		return err
	}
	c.markHealthy()
	return nil
}

// WatchRevocations delivers termination requests for this node until the
// context ends. It reconnects on failure, because a dropped stream must not
// quietly stop a node from hearing about kills.
func (c *Client) WatchRevocations(ctx context.Context, handle func(*sshproxyv1.Revocation)) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}
		stream, err := c.api.StreamRevocations(ctx, &sshproxyv1.StreamRevocationsRequest{
			NodeId: c.config.NodeID,
		})
		if err == nil {
			backoff = time.Second
			for {
				rev, recvErr := stream.Recv()
				if recvErr != nil {
					err = recvErr
					break
				}
				c.cache.Clear()
				handle(rev)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("pdpclient: revocation stream ended (%v); retrying in %s", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// ReportEvents delivers a batch of audit records.
//
// The caller keeps the batch spooled until this returns without error, so a
// failure here delays delivery rather than losing it. A partial acceptance is
// treated as a failure for the same reason: replaying a few records is
// harmless because the store deduplicates them, whereas dropping any is not.
func (c *Client) ReportEvents(ctx context.Context, nodeID string, events []*sshproxyv1.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	callCtx, cancel := c.callContext(ctx)
	defer cancel()

	stream, err := c.api.ReportEvents(callCtx)
	if err != nil {
		if unreachable(err) {
			c.markUnhealthy(err)
		}
		return err
	}
	if err := stream.Send(&sshproxyv1.AuditEventBatch{NodeId: nodeID, Events: events}); err != nil {
		if unreachable(err) {
			c.markUnhealthy(err)
		}
		return err
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		if unreachable(err) {
			c.markUnhealthy(err)
		}
		return err
	}
	c.markHealthy()
	if resp.GetAccepted() < int64(len(events)) {
		return fmt.Errorf("pdpclient: the control plane accepted %d of %d audit events",
			resp.GetAccepted(), len(events))
	}
	return nil
}
