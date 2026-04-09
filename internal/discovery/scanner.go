// Package discovery provides network asset discovery for auto-registering
// SSH servers. It performs TCP connect scans and SSH banner grabs using only
// the Go standard library.
package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ScanResult holds the outcome of scanning a single host:port.
type ScanResult struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	IsSSH        bool          `json:"is_ssh"`
	SSHVersion   string        `json:"ssh_version,omitempty"`
	HostKey      string        `json:"host_key,omitempty"`
	OS           string        `json:"os,omitempty"`
	ResponseTime time.Duration `json:"response_time"`
	ScannedAt    time.Time     `json:"scanned_at"`
	Status       string        `json:"status"` // "open", "closed", "filtered"
}

// ScanConfig controls the behaviour of a network scan.
type ScanConfig struct {
	Targets     []string      // CIDR ranges or hostnames
	Ports       []int         // ports to scan (default: 22, 2222)
	Timeout     time.Duration // per-host timeout (default: 5s)
	Concurrency int           // max concurrent scans (default: 50)
	SSHBanner   bool          // attempt SSH banner grab
}

// Scanner performs concurrent TCP connect scans with optional SSH banner
// grabbing.
type Scanner struct {
	config *ScanConfig
}

// NewScanner creates a Scanner with the given configuration. Nil or
// zero-valued fields in cfg are replaced with sensible defaults.
func NewScanner(cfg *ScanConfig) *Scanner {
	if cfg == nil {
		cfg = &ScanConfig{}
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []int{22, 2222}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 50
	}
	return &Scanner{config: cfg}
}

// Scan enumerates every IP in the configured targets/CIDRs and scans each
// host:port combination concurrently. Results are returned once all scans
// complete or the context is cancelled.
func (s *Scanner) Scan(ctx context.Context) ([]ScanResult, error) {
	hosts, err := s.enumerateHosts()
	if err != nil {
		return nil, fmt.Errorf("enumerate hosts: %w", err)
	}

	type job struct {
		host string
		port int
	}

	var jobs []job
	for _, h := range hosts {
		for _, p := range s.config.Ports {
			jobs = append(jobs, job{host: h, port: p})
		}
	}

	var (
		mu      sync.Mutex
		results []ScanResult
		wg      sync.WaitGroup
	)

	// Buffered channel acts as a concurrency semaphore.
	sem := make(chan struct{}, s.config.Concurrency)

	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{} // acquire

		go func(h string, p int) {
			defer wg.Done()
			defer func() { <-sem }() // release

			res, scanErr := s.ScanHost(ctx, h, p)
			if scanErr != nil {
				return
			}
			mu.Lock()
			results = append(results, *res)
			mu.Unlock()
		}(j.host, j.port)
	}

	wg.Wait()
	return results, ctx.Err()
}

// ScanHost performs a single TCP connect scan against host:port with an
// optional SSH banner grab.
func (s *Scanner) ScanHost(ctx context.Context, host string, port int) (*ScanResult, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	result := &ScanResult{
		Host:      host,
		Port:      port,
		ScannedAt: time.Now().UTC(),
	}

	start := time.Now()

	dialer := net.Dialer{Timeout: s.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	result.ResponseTime = time.Since(start)

	if err != nil {
		if isTimeout(err) {
			result.Status = "filtered"
		} else {
			result.Status = "closed"
		}
		return result, nil
	}
	defer conn.Close()

	result.Status = "open"

	if s.config.SSHBanner {
		_ = conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err == nil {
			banner := strings.TrimSpace(line)
			if strings.HasPrefix(banner, "SSH-") {
				result.IsSSH = true
				result.SSHVersion = banner
				result.OS = GuessOS(banner)
			}
		}
	}

	return result, nil
}

// enumerateHosts expands all configured targets (CIDRs and plain hosts) into
// individual IP address strings.
func (s *Scanner) enumerateHosts() ([]string, error) {
	var hosts []string
	seen := make(map[string]bool)

	for _, target := range s.config.Targets {
		if strings.Contains(target, "/") {
			ips, err := ExpandCIDR(target)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", target, err)
			}
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					hosts = append(hosts, ip)
				}
			}
		} else {
			if !seen[target] {
				seen[target] = true
				hosts = append(hosts, target)
			}
		}
	}
	return hosts, nil
}

// ExpandCIDR returns every usable host IP in the given CIDR range.
// For ranges larger than /16 it returns an error to prevent accidental
// enumeration of huge blocks.
func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipNet.Mask.Size()
	if bits-ones > 16 {
		return nil, fmt.Errorf("CIDR range /%d is too large (max /16)", ones)
	}

	var ips []string
	for current := cloneIP(ip.Mask(ipNet.Mask)); ipNet.Contains(current); incIP(current) {
		ips = append(ips, current.String())
	}

	// Remove network and broadcast addresses for IPv4 /31 and larger.
	if len(ips) > 2 && ip.To4() != nil {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

// GuessOS attempts to determine the operating system from an SSH version
// banner string.
func GuessOS(banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ubuntu"):
		return "Ubuntu"
	case strings.Contains(lower, "debian"):
		return "Debian"
	case strings.Contains(lower, "freebsd"):
		return "FreeBSD"
	case strings.Contains(lower, "centos"):
		return "CentOS"
	case strings.Contains(lower, "redhat") || strings.Contains(lower, "red hat"):
		return "RedHat"
	case strings.Contains(lower, "fedora"):
		return "Fedora"
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "openssh"):
		return "Linux"
	case strings.Contains(lower, "dropbear"):
		return "Linux/Embedded"
	default:
		return ""
	}
}

// ParseSSHBanner extracts the protocol version and software string from an
// SSH identification string such as "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".
func ParseSSHBanner(banner string) (proto, software string) {
	banner = strings.TrimSpace(banner)
	if !strings.HasPrefix(banner, "SSH-") {
		return "", ""
	}
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) < 3 {
		return "", ""
	}
	proto = parts[0] + "-" + parts[1] // "SSH-2.0"
	software = parts[2]
	return proto, software
}

// --- helpers ---

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	// Work on the 4-byte or 16-byte representation.
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}
