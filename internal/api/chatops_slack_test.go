package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func TestHandleSlackChatOpsApproveJITRequest(t *testing.T) {
	api, mux, store := setupJITTestAPI(t)
	api.config.JITChatOpsSlackSigningSecret = "slack-secret"
	if err := api.users.create(models.User{Username: "admin-bob", Role: "admin"}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	req := &jit.AccessRequest{
		Requester: "alice",
		Target:    "prod-db",
		Role:      "operator",
		Reason:    "maintenance",
		Duration:  time.Hour,
	}
	if err := store.CreateRequest(req); err != nil {
		t.Fatalf("CreateRequest() error = %v", err)
	}

	body := url.Values{
		"command":   {"/sshproxy"},
		"user_name": {"admin-bob"},
		"text":      {"jit approve " + req.ID},
	}.Encode()
	reqTime := time.Now().UTC()
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v2/chatops/slack/commands", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("X-Slack-Request-Timestamp", slackSignedTimestamp(reqTime))
	httpReq.Header.Set("X-Slack-Signature", slackSignedSignature("slack-secret", httpReq.Header.Get("X-Slack-Request-Timestamp"), body))
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	updated, err := store.GetRequest(req.ID)
	if err != nil {
		t.Fatalf("GetRequest() error = %v", err)
	}
	if updated.Status != jit.StatusApproved {
		t.Fatalf("status = %s, want %s", updated.Status, jit.StatusApproved)
	}
	if !strings.Contains(rr.Body.String(), "Approved request") {
		t.Fatalf("response = %s, want approval message", rr.Body.String())
	}
}

func TestHandleSlackChatOpsRejectsInvalidSignature(t *testing.T) {
	api, mux, _ := setupJITTestAPI(t)
	api.config.JITChatOpsSlackSigningSecret = "slack-secret"

	body := url.Values{
		"command":   {"/sshproxy"},
		"user_name": {"admin-bob"},
		"text":      {"jit show req-1"},
	}.Encode()
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v2/chatops/slack/commands", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("X-Slack-Request-Timestamp", slackSignedTimestamp(time.Now().UTC()))
	httpReq.Header.Set("X-Slack-Signature", "v0=deadbeef")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, httpReq)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d body=%s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
}

func slackSignedTimestamp(ts time.Time) string {
	return strconv.FormatInt(ts.Unix(), 10)
}

func slackSignedSignature(secret, timestamp, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":"))
	mac.Write([]byte(body))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}
