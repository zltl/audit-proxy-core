package api

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshAutomationExecutor struct {
	connector *sshClientConnector
}

func newSSHAutomationExecutor() automationExecutor {
	return &sshAutomationExecutor{connector: newSSHClientConnector()}
}

func (e *sshAutomationExecutor) Execute(ctx context.Context, req automationExecutionRequest) automationTargetResult {
	result := automationTargetResult{
		TargetID:   req.Target.ID,
		TargetName: firstAutomationValue(req.Target.Name, req.Target.Host),
		Host:       req.Target.Host,
		Port:       req.Target.Port,
		Status:     "failed",
		StartedAt:  time.Now().UTC(),
	}
	finalClient, cleanup, err := e.connect(ctx, req.Target)
	if err != nil {
		result.Error = err.Error()
		result.Summary = "failed to establish SSH connection"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	defer cleanup()

	session, err := finalClient.NewSession()
	if err != nil {
		result.Error = err.Error()
		result.Summary = "failed to create SSH session"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	defer session.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if req.Script != nil {
		session.Stdin = strings.NewReader(req.Script.Body)
	}

	command := e.command(req)
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case <-ctx.Done():
		_ = finalClient.Close()
		result.Status = "timed_out"
		result.Error = ctx.Err().Error()
		result.Summary = "execution timed out"
	case err = <-done:
		if err == nil {
			result.Status = "completed"
			result.Summary = "command completed successfully"
		} else if exitErr, ok := err.(*ssh.ExitError); ok {
			result.Status = "failed"
			result.ExitCode = exitErr.ExitStatus()
			result.Error = err.Error()
			result.Summary = fmt.Sprintf("command exited with status %d", result.ExitCode)
		} else {
			result.Status = "failed"
			result.Error = err.Error()
			result.Summary = "SSH command execution failed"
		}
	}

	result.Stdout = truncateAutomationOutput(stdout.String(), 64*1024)
	result.Stderr = truncateAutomationOutput(stderr.String(), 64*1024)
	result.FinishedAt = time.Now().UTC()
	return result
}

func (e *sshAutomationExecutor) connect(ctx context.Context, target automationResolvedTarget) (*ssh.Client, func(), error) {
	if e == nil || e.connector == nil {
		e = &sshAutomationExecutor{connector: newSSHClientConnector()}
	}
	return e.connector.Connect(ctx, automationTargetSSHConfig(target))
}

func automationTargetSSHConfig(target automationResolvedTarget) sshTargetConfig {
	hops := make([]sshHopConfig, 0, len(target.JumpChain))
	for _, hop := range target.JumpChain {
		hops = append(hops, sshHopConfig{
			Name:       hop.Name,
			Host:       hop.Host,
			Port:       hop.Port,
			Username:   hop.Username,
			Password:   hop.Password,
			PrivateKey: hop.PrivateKey,
			Passphrase: hop.Passphrase,
		})
	}
	return sshTargetConfig{
		Host:                      target.Host,
		Port:                      target.Port,
		Username:                  target.Username,
		Password:                  target.Password,
		PrivateKey:                target.PrivateKey,
		Passphrase:                target.Passphrase,
		KnownHostsPath:            target.KnownHostsPath,
		InsecureSkipHostKeyVerify: target.InsecureSkipHostKeyVerify,
		JumpChain:                 hops,
	}
}

func resolveAutomationSecret(raw string) (string, error) {
	return resolveSSHSecret(raw)
}

func resolveAutomationPath(raw string) (string, error) {
	return resolveSSHPath(raw)
}

func (e *sshAutomationExecutor) command(req automationExecutionRequest) string {
	envPrefix := automationEnvironmentPrefix(req.Environment)
	if req.Script != nil {
		shell := normalizeAutomationShell(req.Script.Shell)
		return strings.TrimSpace(envPrefix + shell + " -s")
	}
	return strings.TrimSpace(envPrefix + req.Command)
}

func automationEnvironmentPrefix(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value, err := resolveAutomationSecret(values[key])
		if err != nil {
			value = values[key]
		}
		parts = append(parts, key+"="+automationShellQuote(value))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ") + " "
}

func automationShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func truncateAutomationOutput(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "\n...[truncated]"
}
