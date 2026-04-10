package api

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type sshHopConfig struct {
	Name       string
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey string
	Passphrase string
}

type sshTargetConfig struct {
	Host                      string
	Port                      int
	Username                  string
	Password                  string
	PrivateKey                string
	Passphrase                string
	KnownHostsPath            string
	InsecureSkipHostKeyVerify bool
	JumpChain                 []sshHopConfig
}

type sshClientConnector struct {
	dialTimeout time.Duration
}

func newSSHClientConnector() *sshClientConnector {
	return &sshClientConnector{dialTimeout: 10 * time.Second}
}

func (c *sshClientConnector) Connect(ctx context.Context, target sshTargetConfig) (*ssh.Client, func(), error) {
	if c == nil {
		c = newSSHClientConnector()
	}
	target.Port = normalizeSSHPort(target.Port)
	if strings.TrimSpace(target.Host) == "" {
		return nil, func() {}, fmt.Errorf("ssh host is required")
	}
	callback, err := sshHostKeyCallback(target)
	if err != nil {
		return nil, func() {}, err
	}

	nodes := make([]sshTargetConfig, 0, len(target.JumpChain)+1)
	for _, hop := range target.JumpChain {
		nodes = append(nodes, sshTargetConfig{
			Host:                      hop.Host,
			Port:                      normalizeSSHPort(hop.Port),
			Username:                  hop.Username,
			Password:                  hop.Password,
			PrivateKey:                hop.PrivateKey,
			Passphrase:                hop.Passphrase,
			KnownHostsPath:            target.KnownHostsPath,
			InsecureSkipHostKeyVerify: target.InsecureSkipHostKeyVerify,
		})
	}
	nodes = append(nodes, target)

	var clients []*ssh.Client
	cleanup := func() {
		for i := len(clients) - 1; i >= 0; i-- {
			_ = clients[i].Close()
		}
	}

	var currentClient *ssh.Client
	for index, node := range nodes {
		clientConfig, err := sshClientConfig(node, callback)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		addr := net.JoinHostPort(node.Host, fmt.Sprintf("%d", normalizeSSHPort(node.Port)))
		if index == 0 {
			dialer := &net.Dialer{Timeout: c.dialTimeout}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
			client, err := sshClientFromConn(conn, addr, clientConfig)
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
			currentClient = client
			clients = append(clients, client)
			continue
		}
		nextConn, err := currentClient.Dial("tcp", addr)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		client, err := sshClientFromConn(nextConn, addr, clientConfig)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		currentClient = client
		clients = append(clients, client)
	}
	return currentClient, cleanup, nil
}

func normalizeSSHPort(port int) int {
	if port <= 0 {
		return 22
	}
	return port
}

func sshClientFromConn(conn net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

func sshClientConfig(target sshTargetConfig, callback ssh.HostKeyCallback) (*ssh.ClientConfig, error) {
	authMethods, err := sshAuthMethods(target)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:            target.Username,
		Auth:            authMethods,
		HostKeyCallback: callback,
		Timeout:         10 * time.Second,
	}, nil
}

func sshAuthMethods(target sshTargetConfig) ([]ssh.AuthMethod, error) {
	methods := make([]ssh.AuthMethod, 0, 2)
	if strings.TrimSpace(target.PrivateKey) != "" {
		privateKey, err := resolveSSHSecret(target.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("resolve private_key for %s: %w", target.Host, err)
		}
		var signer ssh.Signer
		if strings.TrimSpace(target.Passphrase) != "" {
			passphrase, err := resolveSSHSecret(target.Passphrase)
			if err != nil {
				return nil, fmt.Errorf("resolve passphrase for %s: %w", target.Host, err)
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
			if err != nil {
				return nil, fmt.Errorf("parse encrypted private_key for %s: %w", target.Host, err)
			}
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(privateKey))
			if err != nil {
				return nil, fmt.Errorf("parse private_key for %s: %w", target.Host, err)
			}
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if strings.TrimSpace(target.Password) != "" {
		password, err := resolveSSHSecret(target.Password)
		if err != nil {
			return nil, fmt.Errorf("resolve password for %s: %w", target.Host, err)
		}
		methods = append(methods, ssh.Password(password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH authentication method configured for %s", target.Host)
	}
	return methods, nil
}

func sshHostKeyCallback(target sshTargetConfig) (ssh.HostKeyCallback, error) {
	if target.InsecureSkipHostKeyVerify {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path, err := resolveSSHPath(target.KnownHostsPath)
	if err != nil {
		return nil, err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("known_hosts_path is required for %s", target.Host)
	}
	return knownhosts.New(path)
}

func resolveSSHSecret(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, "${env:") && strings.HasSuffix(value, "}") {
		key := strings.TrimSuffix(strings.TrimPrefix(value, "${env:"), "}")
		resolved, ok := os.LookupEnv(key)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", key)
		}
		return resolved, nil
	}
	if strings.HasPrefix(value, "${file:") && strings.HasSuffix(value, "}") {
		path := strings.TrimSuffix(strings.TrimPrefix(value, "${file:"), "}")
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return value, nil
}

func resolveSSHPath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, "${env:") && strings.HasSuffix(value, "}") {
		key := strings.TrimSuffix(strings.TrimPrefix(value, "${env:"), "}")
		resolved, ok := os.LookupEnv(key)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", key)
		}
		return strings.TrimSpace(resolved), nil
	}
	return value, nil
}
