package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

const slackSignatureMaxSkew = 5 * time.Minute

type slackCommandResponse struct {
	ResponseType string `json:"response_type"`
	Text         string `json:"text"`
}

func (a *API) requireSlackChatOps() error {
	if a == nil || a.jitStore == nil {
		return fmt.Errorf("JIT access is not enabled")
	}
	if a.config == nil || strings.TrimSpace(a.config.JITChatOpsSlackSigningSecret) == "" {
		return fmt.Errorf("Slack ChatOps approval bot is not enabled")
	}
	return nil
}

func (a *API) handleSlackChatOpsCommand(w http.ResponseWriter, r *http.Request) {
	if err := a.requireSlackChatOps(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, "read request body", http.StatusBadRequest)
		return
	}
	if err := verifySlackSignature(
		strings.TrimSpace(a.config.JITChatOpsSlackSigningSecret),
		r.Header.Get("X-Slack-Signature"),
		r.Header.Get("X-Slack-Request-Timestamp"),
		body,
		time.Now().UTC(),
	); err != nil {
		http.Error(w, "invalid slack signature", http.StatusUnauthorized)
		return
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "invalid form payload", http.StatusBadRequest)
		return
	}
	actor := strings.TrimSpace(values.Get("user_name"))
	if actor == "" {
		actor = strings.TrimSpace(values.Get("user_id"))
	}
	if actor == "" {
		writeSlackCommandResponse(w, http.StatusOK, "Unable to determine the Slack user for this command.")
		return
	}

	user, ok, err := a.lookupSlackChatOpsUser(actor)
	if err != nil {
		http.Error(w, "lookup approver", http.StatusInternalServerError)
		return
	}
	if !ok {
		writeSlackCommandResponse(w, http.StatusOK, "No matching local control-plane user was found for Slack user `"+actor+"`.")
		return
	}

	text := strings.TrimSpace(values.Get("text"))
	responseText := a.executeSlackChatOpsCommand(user.Username, user.Role, text)
	writeSlackCommandResponse(w, http.StatusOK, responseText)
}

func verifySlackSignature(secret, signature, timestamp string, body []byte, now time.Time) error {
	secret = strings.TrimSpace(secret)
	signature = strings.TrimSpace(signature)
	timestamp = strings.TrimSpace(timestamp)
	if secret == "" || signature == "" || timestamp == "" {
		return fmt.Errorf("missing signature inputs")
	}
	issuedAt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	ts := time.Unix(issuedAt, 0).UTC()
	if now.Sub(ts) > slackSignatureMaxSkew || ts.Sub(now) > slackSignatureMaxSkew {
		return fmt.Errorf("stale timestamp")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":"))
	mac.Write(body)
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func (a *API) lookupSlackChatOpsUser(actor string) (models.User, bool, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return models.User{}, false, nil
	}
	user, ok, err := a.users.get(actor)
	if err != nil || ok {
		return user, ok, err
	}
	return a.users.get(strings.ToLower(actor))
}

func (a *API) executeSlackChatOpsCommand(actor, role, raw string) string {
	args := normalizeSlackChatOpsArgs(raw)
	if len(args) == 0 {
		return slackChatOpsUsage()
	}

	switch args[0] {
	case "show":
		if len(args) < 2 {
			return "Usage: " + slackChatOpsUsage()
		}
		req, err := a.jitStore.GetRequest(args[1])
		if err != nil {
			return "Request `" + args[1] + "` was not found."
		}
		if !canSlackChatOpsViewRequest(req, actor, role) {
			return "You are not allowed to view request `" + args[1] + "`."
		}
		return renderSlackChatOpsRequest(req)
	case "approve":
		if len(args) < 2 {
			return "Usage: " + slackChatOpsUsage()
		}
		if err := a.jitStore.ApproveRequestWithRole(args[1], actor, role); err != nil {
			return "Approve failed: " + err.Error()
		}
		req, _ := a.jitStore.GetRequest(args[1])
		return "Approved request `" + args[1] + "`.\n" + renderSlackChatOpsRequest(req)
	case "deny":
		if len(args) < 2 {
			return "Usage: " + slackChatOpsUsage()
		}
		reason := ""
		if len(args) > 2 {
			reason = strings.TrimSpace(strings.Join(args[2:], " "))
		}
		if err := a.jitStore.DenyRequestWithRole(args[1], actor, role, reason); err != nil {
			return "Deny failed: " + err.Error()
		}
		req, _ := a.jitStore.GetRequest(args[1])
		return "Denied request `" + args[1] + "`.\n" + renderSlackChatOpsRequest(req)
	default:
		return slackChatOpsUsage()
	}
}

func normalizeSlackChatOpsArgs(raw string) []string {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return nil
	}
	if strings.EqualFold(fields[0], "jit") {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return nil
	}
	fields[0] = strings.ToLower(fields[0])
	return fields
}

func slackChatOpsUsage() string {
	return "Use `jit show <request-id>`, `jit approve <request-id>`, or `jit deny <request-id> [reason]`."
}

func canSlackChatOpsViewRequest(req *jit.AccessRequest, actor, role string) bool {
	if req == nil {
		return false
	}
	if strings.TrimSpace(actor) != "" && req.Requester == actor {
		return true
	}
	return roleAllowed(req.CurrentApproverRoles, role)
}

func roleAllowed(roles []string, role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	for _, candidate := range roles {
		if strings.TrimSpace(candidate) == role {
			return true
		}
	}
	return false
}

func renderSlackChatOpsRequest(req *jit.AccessRequest) string {
	if req == nil {
		return "Request not found."
	}
	lines := []string{
		"ID: " + req.ID,
		"Requester: " + req.Requester,
		"Target: " + req.Target,
		"Role: " + req.Role,
		"Status: " + string(req.Status),
		"Duration: " + req.Duration.String(),
	}
	if req.Reason != "" {
		lines = append(lines, "Reason: "+req.Reason)
	}
	if req.Approver != "" {
		lines = append(lines, "Approver: "+req.Approver)
	}
	if len(req.CurrentApproverRoles) > 0 {
		lines = append(lines, "Current Approver Roles: "+strings.Join(req.CurrentApproverRoles, ","))
	}
	if !req.CreatedAt.IsZero() {
		lines = append(lines, "Created At: "+req.CreatedAt.UTC().Format(time.RFC3339))
	}
	if !req.ExpiresAt.IsZero() {
		lines = append(lines, "Expires At: "+req.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if req.DenyReason != "" {
		lines = append(lines, "Deny Reason: "+req.DenyReason)
	}
	return strings.Join(lines, "\n")
}

func writeSlackCommandResponse(w http.ResponseWriter, status int, text string) {
	if strings.TrimSpace(text) == "" {
		text = "Done."
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(slackCommandResponse{
		ResponseType: "ephemeral",
		Text:         text,
	})
}
