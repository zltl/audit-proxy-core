// Command control-plane starts the SSH Proxy control-plane HTTP server.
//
// Usage:
//
//	control-plane [-config path] [-addr :8443]
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/server"
)

func main() {
	configPath := flag.String("config", "", "path to JSON config file")
	addr := flag.String("addr", "", "override listen address (e.g. :8443)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *addr != "" {
		cfg.ListenAddr = *addr
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	// Start the server in a goroutine so we can block on signals.
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()

	// Wait for interrupt / SIGTERM.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("received signal %v, shutting down…", sig)
	case err := <-errCh:
		log.Fatalf("server exited: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}
	log.Println("server stopped")
}
