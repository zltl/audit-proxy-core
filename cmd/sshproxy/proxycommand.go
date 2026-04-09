package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

func runProxyCommand(args []string) {
	fs := flag.NewFlagSet("proxycommand", flag.ExitOnError)
	addr := fs.String("addr", "", "SSH proxy TCP address (defaults to config ssh_addr or SSHPROXY_SSH_ADDR)")
	timeout := fs.Duration("timeout", 10*time.Second, "TCP dial timeout")
	fs.Parse(args)

	cfg := loadConfig()
	targetAddr := *addr
	if targetAddr == "" {
		targetAddr = cfg.SSHAddr
	}
	if targetAddr == "" {
		printError("missing SSH proxy address; set --addr, ssh_addr in ~/.sshproxy/config.json, or SSHPROXY_SSH_ADDR")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := proxyStream(ctx, targetAddr, os.Stdin, os.Stdout); err != nil {
		printError(fmt.Sprintf("proxycommand failed: %v", err))
		os.Exit(1)
	}
}

func proxyStream(ctx context.Context, addr string, stdin io.Reader, stdout io.Writer) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(conn, stdin)
		if cw, ok := conn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		if err != nil && !errors.Is(err, net.ErrClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	go func() {
		_, err := io.Copy(stdout, conn)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
