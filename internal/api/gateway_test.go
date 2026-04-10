package api

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeGatewayDialer struct {
	mu        sync.Mutex
	targets   []sshTargetConfig
	addresses []string
}

func (f *fakeGatewayDialer) DialContext(_ context.Context, target sshTargetConfig, network, address string) (net.Conn, func(), error) {
	f.mu.Lock()
	f.targets = append(f.targets, target)
	f.addresses = append(f.addresses, address)
	f.mu.Unlock()
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, func() {}, err
	}
	return conn, func() { _ = conn.Close() }, nil
}

func startGatewayEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func closeWrite(t *testing.T, conn net.Conn) {
	t.Helper()
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite() error = %v", err)
		}
	}
}

func TestGatewayProxyLifecycleAndTCPForward(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	dialer := &fakeGatewayDialer{}
	api.gateway = newGatewayState(dialer)

	backendAddr := startGatewayEchoServer(t)
	backendHost, backendPortRaw, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}
	backendPort, err := strconv.Atoi(backendPortRaw)
	if err != nil {
		t.Fatalf("strconv.Atoi() error = %v", err)
	}

	createResp := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/gateway/proxies", map[string]interface{}{
		"protocol":                       "rdp",
		"remote_host":                    backendHost,
		"remote_port":                    backendPort,
		"ssh_host":                       "bastion.internal",
		"username":                       "ops",
		"password":                       "secret",
		"insecure_skip_host_key_verify":  true,
	}, map[string]string{"X-User": "admin"})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/gateway/proxies status = %d body = %s", createResp.Code, createResp.Body.String())
	}
	created := parseResponse(t, createResp)
	proxy := created.Data.(map[string]interface{})
	localAddress := proxy["local_address"].(string)
	proxyID := proxy["id"].(string)
	if !strings.HasPrefix(proxy["local_url"].(string), "rdp://") {
		t.Fatalf("expected rdp:// local_url, got %v", proxy["local_url"])
	}

	clientConn, err := net.Dial("tcp", localAddress)
	if err != nil {
		t.Fatalf("net.Dial(local proxy) error = %v", err)
	}
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	closeWrite(t, clientConn)
	data, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("proxied payload = %q, want %q", string(data), "hello")
	}

	listResp := doAutomationRequest(t, mux, http.MethodGet, "/api/v2/gateway/proxies", nil, nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/gateway/proxies status = %d body = %s", listResp.Code, listResp.Body.String())
	}
	if parseResponse(t, listResp).Total != 1 {
		t.Fatalf("list total != 1: %s", listResp.Body.String())
	}

	deleteResp := doAutomationRequest(t, mux, http.MethodDelete, "/api/v2/gateway/proxies/"+proxyID, nil, map[string]string{"X-User": "admin"})
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v2/gateway/proxies/{id} status = %d body = %s", deleteResp.Code, deleteResp.Body.String())
	}

	getResp := doAutomationRequest(t, mux, http.MethodGet, "/api/v2/gateway/proxies/"+proxyID, nil, nil)
	if getResp.Code != http.StatusNotFound {
		t.Fatalf("GET deleted gateway proxy status = %d body = %s", getResp.Code, getResp.Body.String())
	}

	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.addresses) == 0 || dialer.addresses[0] != backendAddr {
		t.Fatalf("dialed addresses = %v, want %s", dialer.addresses, backendAddr)
	}
}

func TestGatewaySOCKS5ProxyUsesJumpChain(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	dialer := &fakeGatewayDialer{}
	api.gateway = newGatewayState(dialer)

	backendAddr := startGatewayEchoServer(t)
	backendHost, backendPortRaw, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}
	backendPort, err := strconv.Atoi(backendPortRaw)
	if err != nil {
		t.Fatalf("strconv.Atoi() error = %v", err)
	}

	createResp := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/gateway/proxies", map[string]interface{}{
		"protocol":                      "socks5",
		"ssh_host":                      "bastion.internal",
		"username":                      "ops",
		"password":                      "secret",
		"insecure_skip_host_key_verify": true,
		"jump_chain": []map[string]interface{}{
			{
				"host":     "jump-1.internal",
				"username": "jump",
				"password": "jump-secret",
			},
		},
	}, map[string]string{"X-User": "admin"})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/gateway/proxies socks5 status = %d body = %s", createResp.Code, createResp.Body.String())
	}
	proxy := parseResponse(t, createResp).Data.(map[string]interface{})
	localAddress := proxy["local_address"].(string)
	if proxy["jump_hops"].(float64) != 1 {
		t.Fatalf("jump_hops = %v, want 1", proxy["jump_hops"])
	}

	conn, err := net.Dial("tcp", localAddress)
	if err != nil {
		t.Fatalf("net.Dial(SOCKS5 proxy) error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("SOCKS5 greeting write error = %v", err)
	}
	greetingResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetingResp); err != nil {
		t.Fatalf("SOCKS5 greeting read error = %v", err)
	}
	if greetingResp[1] != 0x00 {
		t.Fatalf("SOCKS5 auth response = %v, want no-auth", greetingResp)
	}
	ip := net.ParseIP(backendHost).To4()
	request := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], 0x00, 0x00}
	binary.BigEndian.PutUint16(request[8:], uint16(backendPort))
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("SOCKS5 connect write error = %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("SOCKS5 connect reply read error = %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS5 connect reply = %v, want success", reply)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("SOCKS5 payload write error = %v", err)
	}
	closeWrite(t, conn)
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("SOCKS5 payload read error = %v", err)
	}
	if string(data) != "ping" {
		t.Fatalf("SOCKS5 proxied payload = %q, want %q", string(data), "ping")
	}

	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.targets) == 0 || len(dialer.targets[0].JumpChain) != 1 {
		t.Fatalf("dial targets = %+v, want one jump hop", dialer.targets)
	}
	if len(dialer.addresses) == 0 || dialer.addresses[0] != backendAddr {
		t.Fatalf("dial addresses = %v, want %s", dialer.addresses, backendAddr)
	}
}

func TestNormalizeGatewayProtocolDefaults(t *testing.T) {
	cases := map[string]int{
		"rdp":        3389,
		"vnc":        5900,
		"mysql":      3306,
		"postgresql": 5432,
		"redis":      6379,
		"kubernetes": 6443,
		"http":       80,
		"https":      443,
		"x11":        6000,
	}
	for protocol, wantPort := range cases {
		gotProtocol, gotPort, err := normalizeGatewayProtocol(protocol)
		if err != nil {
			t.Fatalf("normalizeGatewayProtocol(%q) error = %v", protocol, err)
		}
		if gotProtocol == "" || gotPort != wantPort {
			t.Fatalf("normalizeGatewayProtocol(%q) = (%q, %d), want port %d", protocol, gotProtocol, gotPort, wantPort)
		}
	}
	if _, _, err := normalizeGatewayProtocol("unknown"); err == nil {
		t.Fatal("normalizeGatewayProtocol(unknown) unexpectedly succeeded")
	}
}
