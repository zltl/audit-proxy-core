package pdpclient

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/iniimport"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// iniFallback evaluates a local config.ini when the decision point is down.
type iniFallback struct {
	path string
	mu   sync.RWMutex
	doc  *iniimport.Document
	mod  time.Time
}

func newINIFallback(path string) *iniFallback {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return &iniFallback{path: strings.TrimSpace(path)}
}

func (f *iniFallback) reload() error {
	if f == nil {
		return nil
	}
	doc, err := iniimport.ParseFile(f.path)
	if err != nil {
		return err
	}
	info, err := os.Stat(f.path)
	if err == nil {
		f.mu.Lock()
		f.doc = doc
		f.mod = info.ModTime()
		f.mu.Unlock()
	} else {
		f.mu.Lock()
		f.doc = doc
		f.mu.Unlock()
	}
	return nil
}

func (f *iniFallback) evaluate(req *sshproxyv1.AuthorizeSessionRequest) (*sshproxyv1.AuthorizeSessionResponse, bool) {
	if f == nil {
		return nil, false
	}
	f.mu.RLock()
	doc := f.doc
	f.mu.RUnlock()
	if doc == nil {
		if err := f.reload(); err != nil {
			log.Printf("pdpclient: ini fallback reload failed: %v", err)
			return nil, false
		}
		f.mu.RLock()
		doc = f.doc
		f.mu.RUnlock()
	}
	if doc == nil {
		return nil, false
	}

	username := strings.TrimSpace(req.GetUsername())
	if username == "" || !iniUserEnabled(doc, username) {
		return &sshproxyv1.AuthorizeSessionResponse{
			Allowed: false,
			Reason:  "ini fallback: user is not permitted",
		}, true
	}

	target := strings.TrimSpace(req.GetTarget())
	if target == "" {
		target = net.JoinHostPort(req.GetTargetHost(), itoa(int(req.GetTargetPort())))
	}
	if !iniRouteAllows(doc, username, target) {
		return &sshproxyv1.AuthorizeSessionResponse{
			Allowed: false,
			Reason:  "ini fallback: no matching route",
		}, true
	}

	log.Printf("pdpclient: admitting %s to %s from ini fallback — the decision point is unreachable", username, target)
	return &sshproxyv1.AuthorizeSessionResponse{
		Allowed:  true,
		Reason:   "admitted from config.ini fallback while the decision point is unreachable",
		Features: []string{"shell", "exec", "pty", "env", "sftp", "download"},
	}, true
}

func iniUserEnabled(doc *iniimport.Document, username string) bool {
	for _, section := range doc.SectionsOfKind("user") {
		if !strings.EqualFold(section.Arg, username) {
			continue
		}
		if enabled, ok := section.Get("enabled"); ok && strings.EqualFold(enabled, "false") {
			return false
		}
		return true
	}
	return false
}

func iniRouteAllows(doc *iniimport.Document, username, target string) bool {
	host, port := splitHostPortDefault(target, 22)
	for _, section := range doc.SectionsOfKind("route") {
		routeUser, _ := section.Get("user")
		if routeUser != "" && !strings.EqualFold(routeUser, username) {
			continue
		}
		routeHost, _ := section.Get("host")
		if routeHost == "" {
			continue
		}
		routePort := 22
		if p, ok := section.Get("port"); ok && strings.TrimSpace(p) != "" {
			if n, err := parseInt(p); err == nil {
				routePort = n
			}
		}
		if strings.EqualFold(routeHost, host) && routePort == port {
			return true
		}
	}
	return false
}

func splitHostPortDefault(target string, defaultPort int) (string, int) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return strings.TrimSpace(target), defaultPort
	}
	port := defaultPort
	if n, err := parseInt(portText); err == nil {
		port = n
	}
	return host, port
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
