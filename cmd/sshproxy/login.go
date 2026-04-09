package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type cliLoginStart struct {
	ChallengeID string `json:"challenge_id"`
	PollToken   string `json:"poll_token"`
	AuthURL     string `json:"auth_url"`
}

type cliLoginStatus struct {
	Status        string `json:"status"`
	Username      string `json:"username"`
	SessionCookie string `json:"session_cookie"`
}

type signedCertificateResponse struct {
	Certificate string `json:"certificate"`
	Serial      uint64 `json:"serial"`
	KeyID       string `json:"key_id"`
	ExpiresAt   string `json:"expires_at"`
}

func runLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	ttl := fs.String("ttl", "8h", "certificate TTL")
	keyPathFlag := fs.String("key", defaultIdentityPath(), "private key path (generated if missing)")
	certPathFlag := fs.String("cert", "", "certificate output path (default <key>-cert.pub)")
	principalsFlag := fs.String("principals", "", "comma-separated principals (defaults to the authenticated username)")
	timeout := fs.Duration("timeout", 5*time.Minute, "maximum time to wait for browser authentication")
	noBrowser := fs.Bool("no-browser", false, "do not attempt to open the browser automatically")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	cfg := loadConfig()
	if cfg.Server == "" {
		printError("missing control-plane server; set server in ~/.sshproxy/config.json or SSHPROXY_SERVER")
		os.Exit(1)
	}

	client := NewClientFromConfig(cfg)
	start, err := startCLILogin(client)
	if err != nil {
		printError(fmt.Sprintf("failed to start OIDC login: %v", err))
		os.Exit(1)
	}

	fmt.Printf("Open the following URL to authenticate:\n\n  %s\n\n", start.AuthURL)
	if !*noBrowser {
		if err := openBrowser(start.AuthURL); err != nil {
			printWarning(fmt.Sprintf("failed to open browser automatically: %v", err))
		}
	}

	status, err := waitForCLILogin(client, start.ChallengeID, start.PollToken, *timeout)
	if err != nil {
		printError(fmt.Sprintf("login did not complete: %v", err))
		os.Exit(1)
	}

	cfg.SessionCookie = status.SessionCookie
	if err := saveConfig(cfg); err != nil {
		printError(fmt.Sprintf("failed to save authenticated session: %v", err))
		os.Exit(1)
	}

	sessionClient := NewClientFromConfig(cfg)
	username, err := authenticatedUsername(sessionClient)
	if err != nil {
		printError(fmt.Sprintf("failed to confirm authenticated user: %v", err))
		os.Exit(1)
	}

	keyPath, certPath, err := resolveIdentityPaths(*keyPathFlag, *certPathFlag)
	if err != nil {
		printError(fmt.Sprintf("failed to resolve key paths: %v", err))
		os.Exit(1)
	}

	publicKey, err := ensureIdentityKeyPair(keyPath)
	if err != nil {
		printError(fmt.Sprintf("failed to prepare SSH identity: %v", err))
		os.Exit(1)
	}

	principals := resolvePrincipals(username, *principalsFlag)
	if len(principals) == 0 {
		printError("no certificate principals resolved")
		os.Exit(1)
	}

	cert, err := issueUserCertificate(sessionClient, publicKey, principals, *ttl)
	if err != nil {
		printError(fmt.Sprintf("failed to sign SSH certificate: %v", err))
		os.Exit(1)
	}

	if err := writeSignedCertificate(certPath, cert.Certificate); err != nil {
		printError(fmt.Sprintf("failed to write SSH certificate: %v", err))
		os.Exit(1)
	}

	cfg.IdentityFile = keyPath
	if err := saveConfig(cfg); err != nil {
		printError(fmt.Sprintf("failed to persist SSH identity path: %v", err))
		os.Exit(1)
	}

	printSuccess(fmt.Sprintf("Logged in as %s and wrote an SSH certificate valid until %s", username, formatTime(cert.ExpiresAt)))
	fmt.Printf("Identity: %s\nCertificate: %s\n", keyPath, certPath)
}

func startCLILogin(client *Client) (*cliLoginStart, error) {
	data, err := client.Post("/api/v2/cli/login/start", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	var start cliLoginStart
	if err := json.Unmarshal(data, &start); err != nil {
		return nil, fmt.Errorf("parse CLI login response: %w", err)
	}
	if start.ChallengeID == "" || start.PollToken == "" || start.AuthURL == "" {
		return nil, errors.New("CLI login start response is incomplete")
	}
	return &start, nil
}

func waitForCLILogin(client *Client, challengeID, pollToken string, timeout time.Duration) (*cliLoginStatus, error) {
	deadline := time.Now().Add(timeout)
	path := "/api/v2/cli/login/status/" + challengeID + "?poll_token=" + pollToken

	for {
		resp, err := client.GetRaw(path)
		if err != nil {
			return nil, err
		}

		var envelope struct {
			Success bool           `json:"success"`
			Data    cliLoginStatus `json:"data"`
		}
		if err := json.Unmarshal(resp.Body, &envelope); err != nil {
			return nil, fmt.Errorf("parse CLI login status: %w", err)
		}

		if resp.StatusCode == 200 && envelope.Data.Status == "authenticated" {
			if envelope.Data.SessionCookie == "" {
				return nil, errors.New("CLI login completed without a session cookie")
			}
			return &envelope.Data, nil
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out after %s", timeout.Round(time.Second))
		}
		time.Sleep(time.Second)
	}
}

func authenticatedUsername(client *Client) (string, error) {
	data, err := client.Get("/api/v1/auth/me")
	if err != nil {
		return "", err
	}

	var me struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(data, &me); err != nil {
		return "", fmt.Errorf("parse authenticated user: %w", err)
	}
	if me.Username == "" {
		return "", errors.New("authenticated user response did not include a username")
	}
	return me.Username, nil
}

func issueUserCertificate(client *Client, publicKey string, principals []string, ttl string) (*signedCertificateResponse, error) {
	body := map[string]interface{}{
		"public_key": publicKey,
		"principals": principals,
	}
	if ttl != "" {
		body["ttl"] = ttl
	}

	data, err := client.Post("/api/v2/ca/sign-user", body)
	if err != nil {
		return nil, err
	}

	var cert signedCertificateResponse
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("parse certificate response: %w", err)
	}
	if cert.Certificate == "" {
		return nil, errors.New("certificate response did not include a signed certificate")
	}
	return &cert, nil
}

func resolvePrincipals(primary, csv string) []string {
	var principals []string
	seen := make(map[string]struct{})

	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		principals = append(principals, value)
	}

	add(primary)
	for _, part := range strings.Split(csv, ",") {
		add(part)
	}
	return principals
}

func defaultIdentityPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sshproxy/id_ed25519"
	}
	return filepath.Join(home, ".sshproxy", "id_ed25519")
}

func resolveIdentityPaths(keyPath, certPath string) (string, string, error) {
	resolvedKey, err := expandHomePath(keyPath)
	if err != nil {
		return "", "", err
	}
	resolvedCert := certPath
	if resolvedCert == "" {
		resolvedCert = resolvedKey + "-cert.pub"
	}
	resolvedCert, err = expandHomePath(resolvedCert)
	if err != nil {
		return "", "", err
	}
	return resolvedKey, resolvedCert, nil
}

func expandHomePath(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
}

func ensureIdentityKeyPair(keyPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return "", fmt.Errorf("create identity directory: %w", err)
	}

	pubPath := keyPath + ".pub"
	if _, err := os.Stat(keyPath); err == nil {
		if publicKey, err := readAuthorizedKey(pubPath); err == nil {
			return publicKey, nil
		}

		publicKey, err := deriveAuthorizedKey(keyPath)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(pubPath, []byte(publicKey+"\n"), 0o644); err != nil {
			return "", fmt.Errorf("write public key: %w", err)
		}
		return publicKey, nil
	}

	publicKey, privatePEM, err := generateED25519Identity()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(keyPath, privatePEM, 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(publicKey+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}
	return publicKey, nil
}

func readAuthorizedKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func deriveAuthorizedKey(keyPath string) (string, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read private key: %w", err)
	}
	rawKey, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func generateED25519Identity() (publicKey string, privatePEM []byte, err error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generate ED25519 key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("create SSH signer: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("marshal private key: %w", err)
	}

	privatePEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), privatePEM, nil
}

func writeSignedCertificate(path, certificate string) error {
	return os.WriteFile(path, []byte(strings.TrimSpace(certificate)+"\n"), 0o644)
}

func openBrowser(target string) error {
	command, args, err := browserCommand(target)
	if err != nil {
		return err
	}
	return exec.Command(command, args...).Start()
}

func browserCommand(target string) (string, []string, error) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{target}, nil
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", target}, nil
	default:
		if _, err := exec.LookPath("xdg-open"); err == nil {
			return "xdg-open", []string{target}, nil
		}
		if _, err := exec.LookPath("gio"); err == nil {
			return "gio", []string{"open", target}, nil
		}
		return "", nil, errors.New("no supported browser opener found")
	}
}
