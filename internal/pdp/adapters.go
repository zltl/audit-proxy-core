package pdp

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cmdctrl"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
)

// JITGrantChecker adapts the JIT store to GrantChecker.
type JITGrantChecker struct {
	Store *jit.Store
}

func (g JITGrantChecker) HasGrant(username, target string) bool {
	if g.Store == nil {
		return false
	}
	_, ok := g.Store.CheckAccess(username, target)
	return ok
}

// CmdCtrlApprover adapts the command-control approval manager to CommandApprover.
type CmdCtrlApprover struct {
	Manager *cmdctrl.ApprovalManager
}

func (a CmdCtrlApprover) Request(_ context.Context, sessionID, username, target, command, ruleID string) (string, error) {
	if a.Manager == nil {
		return "", fmt.Errorf("pdp: command approval is not configured")
	}
	id := uuid.NewString()
	if err := a.Manager.RequestApproval(&cmdctrl.ApprovalRequest{
		ID:        id,
		SessionID: sessionID,
		Username:  username,
		Command:   command,
		Target:    target,
		RuleID:    ruleID,
	}); err != nil {
		return "", err
	}
	return id, nil
}

func (a CmdCtrlApprover) Await(ctx context.Context, approvalID string) (bool, string, error) {
	if a.Manager == nil {
		return false, "", fmt.Errorf("pdp: command approval is not configured")
	}
	type result struct {
		req *cmdctrl.ApprovalRequest
		err error
	}
	ch := make(chan result, 1)
	go func() {
		req, err := a.Manager.WaitForDecision(approvalID, 0)
		ch <- result{req: req, err: err}
	}()
	select {
	case <-ctx.Done():
		return false, "", ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return false, "", res.err
		}
		switch res.req.Status {
		case "approved":
			return true, res.req.Approver, nil
		case "denied":
			return false, res.req.Approver, nil
		default:
			return false, "", fmt.Errorf("approval ended with status %q", res.req.Status)
		}
	}
}
