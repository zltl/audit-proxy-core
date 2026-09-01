package api

import (
	"context"
	"strings"
	"testing"
)

func TestConnectRefusesInsecureHostKeysUnlessPolicyAllows(t *testing.T) {
	target := sshTargetConfig{
		Host:                      "192.0.2.1",
		Username:                  "someone",
		Password:                  "pw",
		InsecureSkipHostKeyVerify: true,
	}

	// Default policy: a request cannot switch off host key verification.
	_, _, err := newSSHClientConnector().Connect(context.Background(), target)
	if err == nil {
		t.Fatal("expected the connector to refuse insecure_skip_host_key_verify")
	}
	if !strings.Contains(err.Error(), "ssh_allow_insecure_host_keys") {
		t.Fatalf("error should name the setting that permits it, got: %v", err)
	}

	// With the policy enabled the request is honoured, so the call proceeds past
	// the policy check and fails on the network instead. A cancelled context
	// keeps the test from waiting out the dial timeout.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = newSSHClientConnectorWithPolicy(true).Connect(ctx, target)
	if err != nil && strings.Contains(err.Error(), "ssh_allow_insecure_host_keys") {
		t.Fatalf("policy still rejected the request after being enabled: %v", err)
	}
}

func TestHostKeyCallbackRequiresKnownHostsWhenVerifying(t *testing.T) {
	_, err := sshHostKeyCallback(sshTargetConfig{Host: "example.internal"})
	if err == nil {
		t.Fatal("expected an error when neither known_hosts nor an opt-out is set")
	}
	if !strings.Contains(err.Error(), "known_hosts_path") {
		t.Fatalf("error should point at the missing known_hosts_path, got: %v", err)
	}
}
