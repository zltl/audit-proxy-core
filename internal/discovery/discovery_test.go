package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// ---- CIDR Parsing and IP Enumeration ----

func TestExpandCIDR_Slash24(t *testing.T) {
	ips, err := ExpandCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 254 {
		t.Errorf("expected 254 IPs, got %d", len(ips))
	}
	if ips[0] != "192.168.1.1" {
		t.Errorf("expected first IP 192.168.1.1, got %s", ips[0])
	}
	if ips[len(ips)-1] != "192.168.1.254" {
		t.Errorf("expected last IP 192.168.1.254, got %s", ips[len(ips)-1])
	}
}

func TestExpandCIDR_Slash30(t *testing.T) {
	ips, err := ExpandCIDR("10.0.0.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(ips))
	}
}

func TestExpandCIDR_Slash32(t *testing.T) {
	ips, err := ExpandCIDR("10.0.0.5/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Errorf("expected 1 IP, got %d", len(ips))
	}
	if ips[0] != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %s", ips[0])
	}
}

func TestExpandCIDR_TooLarge(t *testing.T) {
	_, err := ExpandCIDR("10.0.0.0/8")
	if err == nil {
		t.Fatal("expected error for /8 range")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExpandCIDR_Invalid(t *testing.T) {
	_, err := ExpandCIDR("not-a-cidr")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// ---- SSH Banner Parsing ----

func TestParseSSHBanner_OpenSSH(t *testing.T) {
	proto, software := ParseSSHBanner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
	if proto != "SSH-2.0" {
		t.Errorf("expected proto SSH-2.0, got %s", proto)
	}
	if !strings.HasPrefix(software, "OpenSSH_8.9") {
		t.Errorf("expected OpenSSH_8.9 prefix, got %s", software)
	}
}

func TestParseSSHBanner_Dropbear(t *testing.T) {
	proto, software := ParseSSHBanner("SSH-2.0-dropbear_2020.81")
	if proto != "SSH-2.0" {
		t.Errorf("expected proto SSH-2.0, got %s", proto)
	}
	if !strings.HasPrefix(software, "dropbear") {
		t.Errorf("expected dropbear prefix, got %s", software)
	}
}

func TestParseSSHBanner_Invalid(t *testing.T) {
	proto, software := ParseSSHBanner("HTTP/1.1 200 OK")
	if proto != "" || software != "" {
		t.Error("expected empty results for non-SSH banner")
	}
}

func TestParseSSHBanner_Empty(t *testing.T) {
	proto, software := ParseSSHBanner("")
	if proto != "" || software != "" {
		t.Error("expected empty results for empty banner")
	}
}

// ---- OS Detection ----

func TestGuessOS_Ubuntu(t *testing.T) {
	os := GuessOS("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
	if os != "Ubuntu" {
		t.Errorf("expected Ubuntu, got %s", os)
	}
}

func TestGuessOS_Debian(t *testing.T) {
	os := GuessOS("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1")
	if os != "Debian" {
		t.Errorf("expected Debian, got %s", os)
	}
}

func TestGuessOS_FreeBSD(t *testing.T) {
	os := GuessOS("SSH-2.0-OpenSSH_8.8 FreeBSD-20211221")
	if os != "FreeBSD" {
		t.Errorf("expected FreeBSD, got %s", os)
	}
}

func TestGuessOS_GenericOpenSSH(t *testing.T) {
	os := GuessOS("SSH-2.0-OpenSSH_9.0")
	if os != "Linux" {
		t.Errorf("expected Linux, got %s", os)
	}
}

func TestGuessOS_Dropbear(t *testing.T) {
	os := GuessOS("SSH-2.0-dropbear_2020.81")
	if os != "Linux/Embedded" {
		t.Errorf("expected Linux/Embedded, got %s", os)
	}
}

func TestGuessOS_Unknown(t *testing.T) {
	os := GuessOS("SSH-2.0-libssh_0.9.6")
	if os != "" {
		t.Errorf("expected empty, got %s", os)
	}
}

// ---- Inventory CRUD ----

func TestInventory_AddFromScan(t *testing.T) {
	inv := NewInventory(t.TempDir())

	results := []ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open", SSHVersion: "SSH-2.0-OpenSSH_8.9"},
		{Host: "10.0.0.2", Port: 22, Status: "open", SSHVersion: "SSH-2.0-OpenSSH_8.4"},
		{Host: "10.0.0.3", Port: 22, Status: "closed"},
	}

	newCount := inv.AddFromScan(results)
	if newCount != 2 {
		t.Errorf("expected 2 new, got %d", newCount)
	}
	if inv.Count() != 2 {
		t.Errorf("expected 2 total, got %d", inv.Count())
	}
}

func TestInventory_Deduplication(t *testing.T) {
	inv := NewInventory(t.TempDir())

	results := []ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open", SSHVersion: "SSH-2.0-OpenSSH_8.9"},
	}
	inv.AddFromScan(results)
	inv.AddFromScan(results) // duplicate

	if inv.Count() != 1 {
		t.Errorf("expected 1 (dedup), got %d", inv.Count())
	}
}

func TestInventory_UpdateOnRescan(t *testing.T) {
	inv := NewInventory(t.TempDir())

	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open", SSHVersion: "SSH-2.0-OpenSSH_8.4"},
	})

	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open", SSHVersion: "SSH-2.0-OpenSSH_9.0"},
	})

	asset, err := inv.Get("10.0.0.1:22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if asset.SSHVersion != "SSH-2.0-OpenSSH_9.0" {
		t.Errorf("expected updated version, got %s", asset.SSHVersion)
	}
}

func TestInventory_Get(t *testing.T) {
	inv := NewInventory(t.TempDir())
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open"},
	})

	asset, err := inv.Get("10.0.0.1:22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if asset.Host != "10.0.0.1" || asset.Port != 22 {
		t.Errorf("unexpected asset: %+v", asset)
	}
}

func TestInventory_GetNotFound(t *testing.T) {
	inv := NewInventory(t.TempDir())
	_, err := inv.Get("no-such-asset")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestInventory_Update(t *testing.T) {
	inv := NewInventory(t.TempDir())
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open"},
	})

	name := "my-server"
	err := inv.Update("10.0.0.1:22", AssetUpdate{Name: &name})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	asset, _ := inv.Get("10.0.0.1:22")
	if asset.Name != "my-server" {
		t.Errorf("expected my-server, got %s", asset.Name)
	}
}

func TestInventory_UpdateNotFound(t *testing.T) {
	inv := NewInventory(t.TempDir())
	name := "x"
	err := inv.Update("no-such", AssetUpdate{Name: &name})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestInventory_Delete(t *testing.T) {
	inv := NewInventory(t.TempDir())
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open"},
	})

	if err := inv.Delete("10.0.0.1:22"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv.Count() != 0 {
		t.Errorf("expected 0, got %d", inv.Count())
	}
}

func TestInventory_DeleteNotFound(t *testing.T) {
	inv := NewInventory(t.TempDir())
	err := inv.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestInventory_ListWithFilter(t *testing.T) {
	inv := NewInventory(t.TempDir())
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open", OS: "Ubuntu"},
		{Host: "10.0.0.2", Port: 22, Status: "open", OS: "Debian"},
	})

	all := inv.List(AssetFilter{})
	if len(all) != 2 {
		t.Errorf("expected 2, got %d", len(all))
	}

	ubuntu := inv.List(AssetFilter{OS: "Ubuntu"})
	if len(ubuntu) != 1 {
		t.Errorf("expected 1, got %d", len(ubuntu))
	}
}

func TestInventory_ListByStatus(t *testing.T) {
	inv := NewInventory(t.TempDir())
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open"},
	})
	status := "registered"
	inv.Update("10.0.0.1:22", AssetUpdate{Status: &status})

	discovered := inv.List(AssetFilter{Status: "discovered"})
	if len(discovered) != 0 {
		t.Errorf("expected 0 discovered, got %d", len(discovered))
	}
	registered := inv.List(AssetFilter{Status: "registered"})
	if len(registered) != 1 {
		t.Errorf("expected 1 registered, got %d", len(registered))
	}
}

func TestInventory_ListByTag(t *testing.T) {
	inv := NewInventory(t.TempDir())
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open"},
	})
	tags := map[string]string{"env": "prod"}
	inv.Update("10.0.0.1:22", AssetUpdate{Tags: tags})

	result := inv.List(AssetFilter{Tag: "env=prod"})
	if len(result) != 1 {
		t.Errorf("expected 1, got %d", len(result))
	}
	result2 := inv.List(AssetFilter{Tag: "env=staging"})
	if len(result2) != 0 {
		t.Errorf("expected 0, got %d", len(result2))
	}
}

func TestInventory_AutoRegister(t *testing.T) {
	inv := NewInventory(t.TempDir())
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open"},
		{Host: "10.0.0.2", Port: 22, Status: "open"},
	})

	auto := true
	inv.Update("10.0.0.1:22", AssetUpdate{AutoRegister: &auto})

	count, err := inv.AutoRegister(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 registered, got %d", count)
	}

	asset, _ := inv.Get("10.0.0.1:22")
	if asset.Status != "registered" {
		t.Errorf("expected registered, got %s", asset.Status)
	}
}

func TestInventory_MarkOffline(t *testing.T) {
	inv := NewInventory(t.TempDir())
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open"},
	})

	// Mark assets older than a future time as offline — shouldn't mark anything
	// since the asset was just seen.
	count := inv.MarkOffline(time.Now().Add(-time.Hour))
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	// Mark all assets as offline.
	count = inv.MarkOffline(time.Now().Add(time.Hour))
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}

func TestInventory_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	inv := NewInventory(dir)
	inv.AddFromScan([]ScanResult{
		{Host: "10.0.0.1", Port: 22, Status: "open", SSHVersion: "SSH-2.0-OpenSSH_8.9"},
	})
	if err := inv.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Load into a new inventory instance.
	inv2 := NewInventory(dir)
	if inv2.Count() != 1 {
		t.Fatalf("expected 1 asset after reload, got %d", inv2.Count())
	}
	asset, _ := inv2.Get("10.0.0.1:22")
	if asset.SSHVersion != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("expected SSH version to persist, got %s", asset.SSHVersion)
	}
}

// ---- Scanner ----

func TestNewScanner_Defaults(t *testing.T) {
	s := NewScanner(nil)
	if s.config.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", s.config.Timeout)
	}
	if s.config.Concurrency != 50 {
		t.Errorf("expected concurrency 50, got %d", s.config.Concurrency)
	}
	if len(s.config.Ports) != 2 {
		t.Errorf("expected 2 default ports, got %d", len(s.config.Ports))
	}
}

func TestScanHost_ClosedPort(t *testing.T) {
	// Scan a port that is almost certainly not open.
	s := NewScanner(&ScanConfig{
		Timeout: 1 * time.Second,
	})

	result, err := s.ScanHost(context.Background(), "127.0.0.1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Port 1 is typically closed.
	if result.Status != "closed" && result.Status != "filtered" {
		t.Errorf("expected closed or filtered, got %s", result.Status)
	}
}

func TestScanHost_OpenPort(t *testing.T) {
	// Start a local TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
	}()

	s := NewScanner(&ScanConfig{Timeout: 2 * time.Second})
	result, err := s.ScanHost(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "open" {
		t.Errorf("expected open, got %s", result.Status)
	}
}

func TestScanHost_SSHBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintln(conn, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
	}()

	s := NewScanner(&ScanConfig{
		Timeout:   2 * time.Second,
		SSHBanner: true,
	})
	result, err := s.ScanHost(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsSSH {
		t.Error("expected IsSSH=true")
	}
	if result.SSHVersion != "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1" {
		t.Errorf("unexpected SSH version: %s", result.SSHVersion)
	}
	if result.OS != "Ubuntu" {
		t.Errorf("expected Ubuntu, got %s", result.OS)
	}
}

func TestScan_Concurrent(t *testing.T) {
	// Start multiple listeners.
	var listeners []net.Listener
	var ports []int

	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		listeners = append(listeners, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)

		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				fmt.Fprintln(conn, "SSH-2.0-TestSSH_1.0")
				conn.Close()
			}
		}(ln)
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	s := NewScanner(&ScanConfig{
		Targets:     []string{"127.0.0.1"},
		Ports:       ports,
		Timeout:     2 * time.Second,
		Concurrency: 10,
		SSHBanner:   true,
	})

	results, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	openCount := 0
	for _, r := range results {
		if r.Status == "open" {
			openCount++
		}
	}
	if openCount != 3 {
		t.Errorf("expected 3 open ports, got %d", openCount)
	}
}

func TestScan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := NewScanner(&ScanConfig{
		Targets: []string{"10.0.0.0/28"},
		Ports:   []int{22},
		Timeout: 1 * time.Second,
	})

	_, err := s.Scan(ctx)
	// Should complete quickly without error or with context.Canceled
	if err != nil && err != context.Canceled {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScan_HostEnumeration(t *testing.T) {
	s := NewScanner(&ScanConfig{
		Targets: []string{"10.0.0.1", "10.0.0.2", "10.0.0.1"}, // duplicate
		Ports:   []int{22},
		Timeout: 100 * time.Millisecond,
	})

	hosts, err := s.enumerateHosts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 unique hosts, got %d: %v", len(hosts), hosts)
	}
}

func TestScan_MixedTargets(t *testing.T) {
	s := NewScanner(&ScanConfig{
		Targets: []string{"10.0.0.0/30", "192.168.1.1"},
		Ports:   []int{22},
		Timeout: 100 * time.Millisecond,
	})

	hosts, err := s.enumerateHosts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 = 2 IPs + 1 standalone = 3 total
	if len(hosts) != 3 {
		t.Errorf("expected 3 hosts, got %d: %v", len(hosts), hosts)
	}
}

func TestScan_InvalidCIDRTarget(t *testing.T) {
	s := NewScanner(&ScanConfig{
		Targets: []string{"invalid/cidr"},
		Ports:   []int{22},
	})

	_, err := s.Scan(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
