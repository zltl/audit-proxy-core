package pdp

import (
	"context"
	"errors"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	auditproxyv1 "github.com/zltl/audit-proxy-core/api/proto/auditproxy/v1"
	"github.com/zltl/audit-proxy-core/internal/store"
	"github.com/zltl/audit-proxy-core/internal/telemetry"
)

// AuthorizeSession decides whether a principal may open a session to a target.
func (s *Server) AuthorizeSession(_ context.Context, req *auditproxyv1.AuthorizeSessionRequest) (*auditproxyv1.AuthorizeSessionResponse, error) {
	target, err := s.resolveTarget(req)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return &auditproxyv1.AuthorizeSessionResponse{
				Allowed: false,
				Reason:  "no such target",
			}, nil
		}
		return nil, status(err, "resolve target")
	}
	if !target.Enabled {
		return &auditproxyv1.AuthorizeSessionResponse{Allowed: false, Reason: "target is disabled"}, nil
	}
	if target.Maintenance {
		return &auditproxyv1.AuthorizeSessionResponse{Allowed: false, Reason: "target is in maintenance"}, nil
	}

	decision, err := s.store.Evaluate(store.AccessRequest{
		Username:      req.GetUsername(),
		Roles:         req.GetRoles(),
		SourceIP:      req.GetClient().GetSourceIp(),
		Target:        target,
		UpstreamLogin: req.GetUpstreamLogin(),
		At:            s.now(),
	})
	if err != nil {
		return nil, status(err, "evaluate access policy")
	}

	// A time-limited grant can permit what the standing rules do not. It is
	// consulted only after the rules refuse, so a grant widens access rather
	// than overriding an explicit denial.
	if !decision.Allowed && s.grants != nil && s.grants.HasGrant(req.GetUsername(), target.Name) {
		decision = store.AccessDecision{
			Allowed:      true,
			Reason:       "allowed by a just-in-time grant",
			RuleName:     "jit-grant",
			Features:     store.FeatureShell | store.FeatureExec | store.FeaturePTY | store.FeatureEnv,
			RecordPolicy: store.RecordFull,
		}
	}

	if !decision.Allowed {
		return &auditproxyv1.AuthorizeSessionResponse{
			Allowed:  false,
			Reason:   decision.Reason,
			RuleId:   decision.RuleID,
			RuleName: decision.RuleName,
		}, nil
	}

	login := strings.TrimSpace(req.GetUpstreamLogin())
	if login == "" {
		if len(decision.UpstreamLogins) > 0 {
			login = decision.UpstreamLogins[0]
		} else {
			login = req.GetUsername()
		}
	}

	approvalRequired := decision.ApprovalRequired
	// A standing JIT grant satisfies session-level approval the same way it
	// satisfies a rule denial: the person already obtained consent.
	if approvalRequired && s.grants != nil && s.grants.HasGrant(req.GetUsername(), target.Name) {
		approvalRequired = false
	}

	return &auditproxyv1.AuthorizeSessionResponse{
		Allowed:            true,
		Reason:             decision.Reason,
		RuleId:             decision.RuleID,
		RuleName:           decision.RuleName,
		TargetId:           target.ID,
		TargetHost:         target.Host,
		TargetPort:         int32(target.Port),
		UpstreamLogin:      login,
		Features:           decision.Features.Names(),
		MaxSessionSeconds:  int64(decision.MaxSessionTTL / time.Second),
		IdleTimeoutSeconds: int64(decision.IdleTimeout / time.Second),
		RecordPolicy:       recordPolicyToProto(decision.RecordPolicy),
		CommandPolicyId:    decision.CommandPolicyID,
		ApprovalRequired:   approvalRequired,
	}, nil
}

// resolveTarget finds the target a request refers to, accepting either a
// registered name or a raw address.
func (s *Server) resolveTarget(req *auditproxyv1.AuthorizeSessionRequest) (store.Target, error) {
	if name := strings.TrimSpace(req.GetTarget()); name != "" {
		if target, err := s.store.GetTarget(name); err == nil {
			return target, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return store.Target{}, err
		}
		// A name that is not registered may still be an address.
		if host, portText, err := net.SplitHostPort(name); err == nil {
			if port, convErr := strconv.Atoi(portText); convErr == nil {
				return s.store.FindTargetByAddress(host, port)
			}
		}
	}
	host := strings.TrimSpace(req.GetTargetHost())
	if host == "" {
		return store.Target{}, store.ErrNotFound
	}
	return s.store.FindTargetByAddress(host, int(req.GetTargetPort()))
}

// --------------------------------------------------------------------------
// Channels
// --------------------------------------------------------------------------

// AuthorizeChannel gates each channel and channel request against the features
// the session was granted.
//
// Checking here rather than only at session start is what stops a session that
// was allowed to run a shell from also opening a tunnel: SSH lets a client ask
// for both on one connection, and the two are very different privileges.
func (s *Server) AuthorizeChannel(_ context.Context, req *auditproxyv1.AuthorizeChannelRequest) (*auditproxyv1.AuthorizeChannelResponse, error) {
	session, err := s.store.GetSession(req.GetSessionId())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return &auditproxyv1.AuthorizeChannelResponse{Allowed: false, Reason: "unknown session"}, nil
		}
		return nil, status(err, "load session")
	}
	if session.Status != store.SessionActive {
		return &auditproxyv1.AuthorizeChannelResponse{Allowed: false, Reason: "session is no longer active"}, nil
	}

	required, ok := requiredFeature(req)
	if !ok {
		return &auditproxyv1.AuthorizeChannelResponse{
			Allowed: false,
			Reason:  "this channel type is not supported",
		}, nil
	}
	if !session.Features.Has(required) {
		return &auditproxyv1.AuthorizeChannelResponse{
			Allowed:         false,
			Reason:          "policy does not permit " + required.String() + " on this session",
			RequiredFeature: required.String(),
		}, nil
	}

	// A transfer is also constrained by direction, which the feature mask
	// carries separately from the protocol that performs it.
	return &auditproxyv1.AuthorizeChannelResponse{Allowed: true}, nil
}

// requiredFeature maps a channel or channel request onto the capability it needs.
func requiredFeature(req *auditproxyv1.AuthorizeChannelRequest) (store.FeatureSet, bool) {
	switch req.GetChannelType() {
	case auditproxyv1.ChannelType_CHANNEL_TYPE_DIRECT_TCPIP:
		return store.FeatureLocalForward, true
	case auditproxyv1.ChannelType_CHANNEL_TYPE_FORWARDED_TCPIP:
		return store.FeatureRemoteForward, true
	case auditproxyv1.ChannelType_CHANNEL_TYPE_X11:
		return store.FeatureX11, true
	case auditproxyv1.ChannelType_CHANNEL_TYPE_AGENT:
		return store.FeatureAgentForward, true
	}

	switch req.GetRequestType() {
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_PTY:
		return store.FeaturePTY, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_SHELL:
		return store.FeatureShell, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_EXEC:
		// scp rides on exec, so an exec that is actually a transfer is charged
		// against the transfer capability rather than the exec one.
		if isSCPCommand(req.GetPayload()) {
			return store.FeatureSCP, true
		}
		return store.FeatureExec, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_SUBSYSTEM:
		if strings.EqualFold(strings.TrimSpace(req.GetPayload()), "sftp") {
			return store.FeatureSFTP, true
		}
		return store.FeatureSubsystem, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_ENV:
		return store.FeatureEnv, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_X11:
		return store.FeatureX11, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_AGENT:
		return store.FeatureAgentForward, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_TCPIP_FORWARD:
		return store.FeatureRemoteForward, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_WINDOW_CHANGE:
		// Resizing an existing terminal grants nothing beyond the pty already
		// allowed, so it is charged against that.
		return store.FeaturePTY, true
	case auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_UNSPECIFIED:
		if req.GetChannelType() == auditproxyv1.ChannelType_CHANNEL_TYPE_SESSION {
			// Opening a session channel by itself does nothing until a request
			// arrives on it, each of which is checked in turn.
			return store.FeatureNone, true
		}
	}
	return store.FeatureNone, false
}

var scpCommandPattern = regexp.MustCompile(`^\s*(/usr/bin/|/bin/)?scp\s`)

func isSCPCommand(command string) bool {
	return scpCommandPattern.MatchString(command)
}

// --------------------------------------------------------------------------
// Commands
// --------------------------------------------------------------------------

// AuthorizeCommand screens a command before it reaches the upstream host.
func (s *Server) AuthorizeCommand(req *auditproxyv1.AuthorizeCommandRequest, stream auditproxyv1.AccessDecisionService_AuthorizeCommandServer) error {
	telemetry.SetSessionID(stream.Context(), req.GetSessionId())

	policyID := strings.TrimSpace(req.GetCommandPolicyId())
	if policyID == "" {
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision: auditproxyv1.CommandDecision_COMMAND_DECISION_ALLOW,
			Reason:   "no command policy is attached to this session",
		})
	}

	rules, err := s.store.ListCommandRules(policyID)
	if err != nil {
		return status(err, "load command rules")
	}
	match, ok := matchCommandRule(rules, req.GetCommand())
	if !ok {
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision: auditproxyv1.CommandDecision_COMMAND_DECISION_ALLOW,
			Reason:   "no rule matched",
		})
	}

	switch match.Action {
	case store.CommandDeny:
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision: auditproxyv1.CommandDecision_COMMAND_DECISION_DENY,
			Reason:   firstNonEmpty(match.Message, "this command is not permitted"),
			RuleId:   match.ID,
			Severity: match.Severity,
		})
	case store.CommandRewrite:
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision:         auditproxyv1.CommandDecision_COMMAND_DECISION_REWRITE,
			Reason:           firstNonEmpty(match.Message, "command was rewritten by policy"),
			RuleId:           match.ID,
			Severity:         match.Severity,
			RewrittenCommand: match.Rewrite,
		})
	case store.CommandAudit:
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision: auditproxyv1.CommandDecision_COMMAND_DECISION_AUDIT,
			Reason:   firstNonEmpty(match.Message, "command was flagged for review"),
			RuleId:   match.ID,
			Severity: match.Severity,
		})
	case store.CommandApprove:
		return s.awaitCommandApproval(req, match, stream)
	default:
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision: auditproxyv1.CommandDecision_COMMAND_DECISION_ALLOW,
			RuleId:   match.ID,
		})
	}
}

// awaitCommandApproval holds the command until a second person rules on it.
//
// The first message tells the data plane the session is waiting, so it can say
// so to the user instead of appearing to hang; the second carries the outcome.
func (s *Server) awaitCommandApproval(
	req *auditproxyv1.AuthorizeCommandRequest,
	rule store.CommandRule,
	stream auditproxyv1.AccessDecisionService_AuthorizeCommandServer,
) error {
	if s.approver == nil {
		// A rule asking for approval with nowhere to send it must refuse.
		// Allowing would quietly turn the strictest action into the weakest.
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision: auditproxyv1.CommandDecision_COMMAND_DECISION_DENY,
			Reason:   "this command requires approval, but no approval workflow is configured",
			RuleId:   rule.ID,
			Severity: rule.Severity,
		})
	}

	ctx := stream.Context()
	approvalID, err := s.approver.Request(ctx, req.GetSessionId(), req.GetUsername(),
		req.GetTarget(), req.GetCommand(), rule.ID)
	if err != nil {
		return status(err, "request command approval")
	}
	if err := stream.Send(&auditproxyv1.AuthorizeCommandResponse{
		Decision:   auditproxyv1.CommandDecision_COMMAND_DECISION_PENDING_APPROVAL,
		Reason:     firstNonEmpty(rule.Message, "waiting for approval"),
		RuleId:     rule.ID,
		Severity:   rule.Severity,
		ApprovalId: approvalID,
	}); err != nil {
		return err
	}

	approved, decidedBy, err := s.approver.Await(ctx, approvalID)
	if err != nil {
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision:   auditproxyv1.CommandDecision_COMMAND_DECISION_DENY,
			Reason:     "approval was not granted: " + err.Error(),
			RuleId:     rule.ID,
			ApprovalId: approvalID,
		})
	}
	if !approved {
		return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
			Decision:   auditproxyv1.CommandDecision_COMMAND_DECISION_DENY,
			Reason:     "denied by " + decidedBy,
			RuleId:     rule.ID,
			ApprovalId: approvalID,
		})
	}
	return stream.Send(&auditproxyv1.AuthorizeCommandResponse{
		Decision:   auditproxyv1.CommandDecision_COMMAND_DECISION_ALLOW,
		Reason:     "approved by " + decidedBy,
		RuleId:     rule.ID,
		ApprovalId: approvalID,
	})
}

// matchCommandRule returns the first enabled rule whose pattern matches.
//
// A rule whose pattern does not compile is skipped rather than treated as a
// match: a broken deny rule that matched everything would take the fleet down,
// and one that matched nothing would silently stop protecting.
func matchCommandRule(rules []store.CommandRule, command string) (store.CommandRule, bool) {
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			log.Printf("pdp: command rule %s has an invalid pattern %q: %v", rule.ID, rule.Pattern, err)
			continue
		}
		if pattern.MatchString(command) {
			return rule, true
		}
	}
	return store.CommandRule{}, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func recordPolicyToProto(p store.RecordPolicy) auditproxyv1.RecordPolicy {
	switch p {
	case store.RecordCommands:
		return auditproxyv1.RecordPolicy_RECORD_POLICY_COMMANDS
	case store.RecordNone:
		return auditproxyv1.RecordPolicy_RECORD_POLICY_NONE
	default:
		return auditproxyv1.RecordPolicy_RECORD_POLICY_FULL
	}
}
