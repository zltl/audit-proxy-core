package pdp

import (
	"context"
	"testing"
	"time"

	"github.com/zltl/audit-proxy-core/internal/cmdctrl"
)

type stubApprover struct {
	approve bool
}

func (s stubApprover) Request(context.Context, string, string, string, string, string) (string, error) {
	return "ap-1", nil
}

func (s stubApprover) Await(context.Context, string) (bool, string, error) {
	return s.approve, "reviewer", nil
}

func TestCmdCtrlApproverAwait(t *testing.T) {
	mgr := cmdctrl.NewApprovalManager(time.Minute, "")
	id := "req-1"
	if err := mgr.RequestApproval(&cmdctrl.ApprovalRequest{ID: id, Username: "alice", Command: "rm -rf /"}); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = mgr.Approve(id, "bob")
	}()
	adapter := CmdCtrlApprover{Manager: mgr}
	ok, by, err := adapter.Await(context.Background(), id)
	if err != nil || !ok || by != "bob" {
		t.Fatalf("await = (%v, %q, %v)", ok, by, err)
	}
}
