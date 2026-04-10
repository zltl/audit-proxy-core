package api

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

var errGatewayProxyNotFound = errors.New("gateway proxy not found")

type gatewayProxyRequest struct {
	Name                      string               `json:"name"`
	Protocol                  string               `json:"protocol"`
	BindAddress               string               `json:"bind_address,omitempty"`
	BindPort                  int                  `json:"bind_port,omitempty"`
	RemoteHost                string               `json:"remote_host,omitempty"`
	RemotePort                int                  `json:"remote_port,omitempty"`
	SSHHost                   string               `json:"ssh_host"`
	SSHPort                   int                  `json:"ssh_port,omitempty"`
	Username                  string               `json:"username"`
	Password                  string               `json:"password,omitempty"`
	PrivateKey                string               `json:"private_key,omitempty"`
	Passphrase                string               `json:"passphrase,omitempty"`
	KnownHostsPath            string               `json:"known_hosts_path,omitempty"`
	InsecureSkipHostKeyVerify bool                 `json:"insecure_skip_host_key_verify,omitempty"`
	JumpChain                 []gatewayHopRequest  `json:"jump_chain,omitempty"`
}

type gatewayHopRequest struct {
	Name       string `json:"name,omitempty"`
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type gatewayProxy struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Protocol     string    `json:"protocol"`
	BindAddress  string    `json:"bind_address"`
	BindPort     int       `json:"bind_port"`
	LocalAddress string    `json:"local_address"`
	LocalURL     string    `json:"local_url,omitempty"`
	RemoteHost   string    `json:"remote_host,omitempty"`
	RemotePort   int       `json:"remote_port,omitempty"`
	SSHHost      string    `json:"ssh_host"`
	SSHPort      int       `json:"ssh_port"`
	Username     string    `json:"username"`
	JumpHops     int       `json:"jump_hops,omitempty"`
	Status       string    `json:"status"`
	LastError    string    `json:"last_error,omitempty"`
	RequestedBy  string    `json:"requested_by,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type gatewayRuntime struct {
	mu       sync.RWMutex
	closeOnce sync.Once
	proxy    gatewayProxy
	target   sshTargetConfig
	listener net.Listener
	closed   chan struct{}
}

type gatewayState struct {
	mu      sync.RWMutex
	proxies map[string]*gatewayRuntime
	dialer  gatewayDialer
}

type gatewayDialer interface {
	DialContext(ctx context.Context, target sshTargetConfig, network, address string) (net.Conn, func(), error)
}

type sshGatewayDialer struct {
	connector *sshClientConnector
}

func newGatewayState(dialer gatewayDialer) *gatewayState {
	if dialer == nil {
		dialer = &sshGatewayDialer{connector: newSSHClientConnector()}
	}
	return &gatewayState{
		proxies: make(map[string]*gatewayRuntime),
		dialer:  dialer,
	}
}

func (d *sshGatewayDialer) DialContext(ctx context.Context, target sshTargetConfig, network, address string) (net.Conn, func(), error) {
	if d == nil || d.connector == nil {
		d = &sshGatewayDialer{connector: newSSHClientConnector()}
	}
	client, cleanup, err := d.connector.Connect(ctx, target)
	if err != nil {
		return nil, func() {}, err
	}
	conn, err := client.Dial(network, address)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return conn, func() {
		_ = conn.Close()
		cleanup()
	}, nil
}

func (s *gatewayState) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	runtimes := make([]*gatewayRuntime, 0, len(s.proxies))
	for id, runtime := range s.proxies {
		delete(s.proxies, id)
		runtimes = append(runtimes, runtime)
	}
	s.mu.Unlock()
	var closeErr error
	for _, runtime := range runtimes {
		if err := runtime.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (s *gatewayState) list() []gatewayProxy {
	if s == nil {
		return []gatewayProxy{}
	}
	s.mu.RLock()
	items := make([]gatewayProxy, 0, len(s.proxies))
	for _, runtime := range s.proxies {
		items = append(items, runtime.snapshot())
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	return items
}

func (s *gatewayState) get(id string) (gatewayProxy, bool) {
	if s == nil {
		return gatewayProxy{}, false
	}
	s.mu.RLock()
	runtime := s.proxies[id]
	s.mu.RUnlock()
	if runtime == nil {
		return gatewayProxy{}, false
	}
	return runtime.snapshot(), true
}

func (s *gatewayState) create(req gatewayProxyRequest, requestedBy string) (gatewayProxy, error) {
	if s == nil {
		return gatewayProxy{}, fmt.Errorf("gateway state is not initialized")
	}
	proxy, target, bind, err := normalizeGatewayProxyRequest(req, requestedBy)
	if err != nil {
		return gatewayProxy{}, err
	}
	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return gatewayProxy{}, err
	}
	addr := listener.Addr().String()
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		proxy.BindPort = tcpAddr.Port
	}
	proxy.LocalAddress = addr
	proxy.LocalURL = gatewayLocalURL(proxy.Protocol, addr)
	runtime := &gatewayRuntime{
		proxy:    proxy,
		target:   target,
		listener: listener,
		closed:   make(chan struct{}),
	}

	s.mu.Lock()
	s.proxies[proxy.ID] = runtime
	s.mu.Unlock()

	go runtime.serve(s.dialer)
	return runtime.snapshot(), nil
}

func (s *gatewayState) stop(id string) error {
	if s == nil {
		return errGatewayProxyNotFound
	}
	s.mu.Lock()
	runtime := s.proxies[id]
	if runtime != nil {
		delete(s.proxies, id)
	}
	s.mu.Unlock()
	if runtime == nil {
		return errGatewayProxyNotFound
	}
	return runtime.Close()
}

func normalizeGatewayProxyRequest(req gatewayProxyRequest, requestedBy string) (gatewayProxy, sshTargetConfig, string, error) {
	protocol, defaultPort, err := normalizeGatewayProtocol(req.Protocol)
	if err != nil {
		return gatewayProxy{}, sshTargetConfig{}, "", err
	}
	bindAddress := strings.TrimSpace(req.BindAddress)
	if bindAddress == "" {
		bindAddress = "127.0.0.1"
	}
	if req.BindPort < 0 || req.BindPort > 65535 {
		return gatewayProxy{}, sshTargetConfig{}, "", fmt.Errorf("bind_port must be between 0 and 65535")
	}
	sshHost := strings.TrimSpace(req.SSHHost)
	if sshHost == "" {
		return gatewayProxy{}, sshTargetConfig{}, "", fmt.Errorf("ssh_host is required")
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return gatewayProxy{}, sshTargetConfig{}, "", fmt.Errorf("username is required")
	}
	remoteHost := strings.TrimSpace(req.RemoteHost)
	remotePort := req.RemotePort
	if protocol != "socks5" {
		if remoteHost == "" {
			remoteHost = "127.0.0.1"
		}
		if remotePort == 0 {
			remotePort = defaultPort
		}
		if remotePort <= 0 || remotePort > 65535 {
			return gatewayProxy{}, sshTargetConfig{}, "", fmt.Errorf("remote_port must be between 1 and 65535")
		}
	}
	jumps := make([]sshHopConfig, 0, len(req.JumpChain))
	for _, hop := range req.JumpChain {
		if strings.TrimSpace(hop.Host) == "" {
			return gatewayProxy{}, sshTargetConfig{}, "", fmt.Errorf("jump_chain host is required")
		}
		if strings.TrimSpace(hop.Username) == "" {
			return gatewayProxy{}, sshTargetConfig{}, "", fmt.Errorf("jump_chain username is required")
		}
		jumps = append(jumps, sshHopConfig{
			Name:       hop.Name,
			Host:       hop.Host,
			Port:       hop.Port,
			Username:   hop.Username,
			Password:   hop.Password,
			PrivateKey: hop.PrivateKey,
			Passphrase: hop.Passphrase,
		})
	}
	target := sshTargetConfig{
		Host:                      sshHost,
		Port:                      normalizeSSHPort(req.SSHPort),
		Username:                  username,
		Password:                  req.Password,
		PrivateKey:                req.PrivateKey,
		Passphrase:                req.Passphrase,
		KnownHostsPath:            req.KnownHostsPath,
		InsecureSkipHostKeyVerify: req.InsecureSkipHostKeyVerify,
		JumpChain:                 jumps,
	}
	if _, err := sshAuthMethods(target); err != nil {
		return gatewayProxy{}, sshTargetConfig{}, "", err
	}
	if _, err := sshHostKeyCallback(target); err != nil {
		return gatewayProxy{}, sshTargetConfig{}, "", err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = defaultGatewayProxyName(protocol, sshHost, remoteHost, remotePort)
	}
	now := time.Now().UTC()
	proxy := gatewayProxy{
		ID:           newAutomationID("proxy"),
		Name:         name,
		Protocol:     protocol,
		BindAddress:  bindAddress,
		BindPort:     req.BindPort,
		RemoteHost:   remoteHost,
		RemotePort:   remotePort,
		SSHHost:      sshHost,
		SSHPort:      target.Port,
		Username:     username,
		JumpHops:     len(jumps),
		Status:       "running",
		RequestedBy:  strings.TrimSpace(requestedBy),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	bind := net.JoinHostPort(bindAddress, fmt.Sprintf("%d", req.BindPort))
	return proxy, target, bind, nil
}

func normalizeGatewayProtocol(raw string) (string, int, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "socks5":
		return "socks5", 0, nil
	case "rdp":
		return "rdp", 3389, nil
	case "vnc":
		return "vnc", 5900, nil
	case "mysql":
		return "mysql", 3306, nil
	case "postgres", "postgresql":
		return "postgresql", 5432, nil
	case "redis":
		return "redis", 6379, nil
	case "kubernetes", "k8s":
		return "kubernetes", 6443, nil
	case "http":
		return "http", 80, nil
	case "https":
		return "https", 443, nil
	case "x11":
		return "x11", 6000, nil
	case "tcp":
		return "tcp", 0, nil
	default:
		return "", 0, fmt.Errorf("unsupported gateway protocol %q", raw)
	}
}

func defaultGatewayProxyName(protocol, sshHost, remoteHost string, remotePort int) string {
	if protocol == "socks5" {
		return fmt.Sprintf("SOCKS5 via %s", sshHost)
	}
	if remoteHost == "" {
		return fmt.Sprintf("%s via %s", strings.ToUpper(protocol), sshHost)
	}
	return fmt.Sprintf("%s %s:%d via %s", strings.ToUpper(protocol), remoteHost, remotePort, sshHost)
}

func gatewayLocalURL(protocol, addr string) string {
	switch protocol {
	case "http":
		return "http://" + addr
	case "https", "kubernetes":
		return "https://" + addr
	case "socks5":
		return "socks5://" + addr
	case "rdp":
		return "rdp://" + addr
	case "vnc":
		return "vnc://" + addr
	case "mysql":
		return "mysql://" + addr
	case "postgresql":
		return "postgresql://" + addr
	case "redis":
		return "redis://" + addr
	case "x11":
		return "x11://" + addr
	default:
		return "tcp://" + addr
	}
}

func (r *gatewayRuntime) snapshot() gatewayProxy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.proxy
}

func (r *gatewayRuntime) setError(err error) {
	if r == nil || err == nil {
		return
	}
	r.mu.Lock()
	r.proxy.LastError = err.Error()
	r.proxy.UpdatedAt = time.Now().UTC()
	r.mu.Unlock()
}

func (r *gatewayRuntime) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	r.closeOnce.Do(func() {
		close(r.closed)
		if r.listener != nil {
			closeErr = r.listener.Close()
		}
		r.mu.Lock()
		r.proxy.Status = "stopped"
		r.proxy.UpdatedAt = time.Now().UTC()
		r.mu.Unlock()
	})
	return closeErr
}

func (r *gatewayRuntime) serve(dialer gatewayDialer) {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
			}
			r.setError(err)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
		go r.handleConn(dialer, conn)
	}
}

func (r *gatewayRuntime) handleConn(dialer gatewayDialer, clientConn net.Conn) {
	defer clientConn.Close()
	proxy := r.snapshot()
	if proxy.Protocol == "socks5" {
		r.handleSOCKS5Conn(dialer, clientConn)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	targetConn, cleanup, err := dialer.DialContext(ctx, r.target, "tcp", net.JoinHostPort(proxy.RemoteHost, fmt.Sprintf("%d", proxy.RemotePort)))
	if err != nil {
		r.setError(err)
		return
	}
	defer cleanup()
	pipeGatewayConns(clientConn, targetConn)
}

func pipeGatewayConns(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(left, right)
		closeGatewayWrite(left)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(right, left)
		closeGatewayWrite(right)
	}()
	wg.Wait()
}

func closeGatewayWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (r *gatewayRuntime) handleSOCKS5Conn(dialer gatewayDialer, clientConn net.Conn) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, request); err != nil {
		return
	}
	if request[0] != 0x05 {
		return
	}
	if request[1] != 0x01 {
		_ = writeSOCKS5Reply(clientConn, 0x07)
		return
	}
	host, port, err := readSOCKS5Address(clientConn, request[3])
	if err != nil {
		_ = writeSOCKS5Reply(clientConn, 0x08)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	targetConn, cleanup, err := dialer.DialContext(ctx, r.target, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		r.setError(err)
		_ = writeSOCKS5Reply(clientConn, 0x01)
		return
	}
	defer cleanup()
	if err := writeSOCKS5Reply(clientConn, 0x00); err != nil {
		return
	}
	pipeGatewayConns(clientConn, targetConn)
}

func readSOCKS5Address(reader io.Reader, atyp byte) (string, int, error) {
	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			return "", 0, err
		}
		return net.IP(addr).String(), int(binary.BigEndian.Uint16(portBytes)), nil
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return "", 0, err
		}
		addr := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			return "", 0, err
		}
		return string(addr), int(binary.BigEndian.Uint16(portBytes)), nil
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			return "", 0, err
		}
		return net.IP(addr).String(), int(binary.BigEndian.Uint16(portBytes)), nil
	default:
		return "", 0, fmt.Errorf("unsupported SOCKS5 address type %d", atyp)
	}
}

func writeSOCKS5Reply(writer io.Writer, code byte) error {
	_, err := writer.Write([]byte{0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func (a *API) RegisterGatewayRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/gateway/proxies", a.handleListGatewayProxies)
	mux.HandleFunc("POST /api/v2/gateway/proxies", a.handleCreateGatewayProxy)
	mux.HandleFunc("GET /api/v2/gateway/proxies/{id}", a.handleGetGatewayProxy)
	mux.HandleFunc("DELETE /api/v2/gateway/proxies/{id}", a.handleDeleteGatewayProxy)
}

func (a *API) handleListGatewayProxies(w http.ResponseWriter, r *http.Request) {
	items := a.gateway.list()
	page, perPage := parsePagination(r)
	total := len(items)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    items[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleCreateGatewayProxy(w http.ResponseWriter, r *http.Request) {
	requestedBy := strings.TrimSpace(r.Header.Get("X-User"))
	if requestedBy == "" {
		writeError(w, http.StatusUnauthorized, "missing X-User header")
		return
	}
	var req gatewayProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	proxy, err := a.gateway.create(req, requestedBy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    proxy,
	})
}

func (a *API) handleGetGatewayProxy(w http.ResponseWriter, r *http.Request) {
	proxy, ok := a.gateway.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errGatewayProxyNotFound.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    proxy,
	})
}

func (a *API) handleDeleteGatewayProxy(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("X-User")) == "" {
		writeError(w, http.StatusUnauthorized, "missing X-User header")
		return
	}
	if err := a.gateway.stop(r.PathValue("id")); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errGatewayProxyNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    "gateway proxy stopped",
	})
}
