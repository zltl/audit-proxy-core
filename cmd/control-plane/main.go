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
	"path/filepath"
	"syscall"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/api"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/server"
)

func main() {
	configPath := flag.String("config", "", "path to JSON config file")
	addr := flag.String("addr", "", "override listen address (e.g. :8443)")
	migrateMode := flag.Bool("migrate", false, "run one-shot data/schema migration and exit")
	migrateTargets := flag.String("migrate-targets", "", "comma-separated migration targets: config,users,audit,session-metadata")
	backupPath := flag.String("backup", "", "write a logical backup bundle to the given file and exit")
	backupTargets := flag.String("backup-targets", "", "comma-separated backup targets: config,users,audit,session-metadata")
	restorePath := flag.String("restore", "", "restore a logical backup bundle from the given file and exit")
	restoreTargets := flag.String("restore-targets", "", "comma-separated restore targets: config,users,audit,session-metadata")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *addr != "" {
		cfg.ListenAddr = *addr
	}
	modeCount := 0
	if *migrateMode {
		modeCount++
	}
	if *backupPath != "" {
		modeCount++
	}
	if *restorePath != "" {
		modeCount++
	}
	if modeCount > 1 {
		log.Fatal("config: only one of -migrate, -backup, or -restore may be used at a time")
	}
	if *migrateMode {
		targets := []string(nil)
		if *migrateTargets != "" {
			targets = []string{*migrateTargets}
		}
		result, err := api.RunDataMigration(buildAPIConfig(cfg), api.MigrationOptions{Targets: targets})
		if err != nil {
			log.Fatalf("migration: %v", err)
		}
		for _, line := range result.SummaryLines() {
			log.Printf("migration: %s", line)
		}
		return
	}
	if *backupPath != "" {
		targets := []string(nil)
		if *backupTargets != "" {
			targets = []string{*backupTargets}
		}
		result, err := api.RunBackup(buildAPIConfig(cfg), *backupPath, api.BackupOptions{Targets: targets})
		if err != nil {
			log.Fatalf("backup: %v", err)
		}
		for _, line := range result.SummaryLines() {
			log.Printf("backup: %s", line)
		}
		return
	}
	if *restorePath != "" {
		targets := []string(nil)
		if *restoreTargets != "" {
			targets = []string{*restoreTargets}
		}
		result, err := api.RunRestore(buildAPIConfig(cfg), *restorePath, api.BackupOptions{Targets: targets})
		if err != nil {
			log.Fatalf("restore: %v", err)
		}
		for _, line := range result.SummaryLines() {
			log.Printf("restore: %s", line)
		}
		return
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

func buildAPIConfig(cfg *config.Config) *api.Config {
	if cfg == nil {
		return &api.Config{}
	}
	return &api.Config{
		AdminUser:                          cfg.AdminUser,
		AdminPassHash:                      cfg.AdminPassHash,
		SessionSecret:                      cfg.SessionSecret,
		AuditLogDir:                        cfg.AuditLogDir,
		RecordingDir:                       cfg.RecordingDir,
		RecordingObjectStorageEnabled:      cfg.RecordingObjectStorageEnabled,
		RecordingObjectStorageEndpoint:     cfg.RecordingObjectStorageEndpoint,
		RecordingObjectStorageBucket:       cfg.RecordingObjectStorageBucket,
		RecordingObjectStorageAccessKey:    cfg.RecordingObjectStorageAccessKey,
		RecordingObjectStorageSecretKey:    cfg.RecordingObjectStorageSecretKey,
		RecordingObjectStorageRegion:       cfg.RecordingObjectStorageRegion,
		RecordingObjectStoragePrefix:       cfg.RecordingObjectStoragePrefix,
		RecordingObjectStorageUseSSL:       cfg.RecordingObjectStorageUseSSL,
		AuditArchiveObjectStorageEnabled:   cfg.AuditArchiveObjectStorageEnabled,
		AuditArchiveObjectStorageEndpoint:  cfg.AuditArchiveObjectStorageEndpoint,
		AuditArchiveObjectStorageBucket:    cfg.AuditArchiveObjectStorageBucket,
		AuditArchiveObjectStorageAccessKey: cfg.AuditArchiveObjectStorageAccessKey,
		AuditArchiveObjectStorageSecretKey: cfg.AuditArchiveObjectStorageSecretKey,
		AuditArchiveObjectStorageRegion:    cfg.AuditArchiveObjectStorageRegion,
		AuditArchiveObjectStoragePrefix:    cfg.AuditArchiveObjectStoragePrefix,
		AuditArchiveObjectStorageUseSSL:    cfg.AuditArchiveObjectStorageUseSSL,
		DataDir:                            cfg.DataDir,
		ConfigFile:                         cfg.DataPlaneConfigFile,
		ConfigVerDir:                       filepath.Join(cfg.DataDir, "config_versions"),
		ConfigApprovalEnabled:              cfg.ConfigApprovalEnabled,
		ConfigStoreBackend:                 cfg.ConfigStoreBackend,
		UserStoreBackend:                   cfg.UserStoreBackend,
		PostgresDatabaseURL:                cfg.PostgresDatabaseURL,
		PostgresReadDatabaseURLs:           cfg.PostgresReadDatabaseURLs,
		AuditStoreBackend:                  cfg.AuditStoreBackend,
		AuditStoreDatabaseURL:              cfg.AuditStoreDatabaseURL,
		AuditStoreReadDatabaseURLs:         cfg.AuditStoreReadDatabaseURLs,
		AuditStoreEndpoint:                 cfg.AuditStoreEndpoint,
		AuditStoreToken:                    cfg.AuditStoreToken,
		AuditStoreUsername:                 cfg.AuditStoreUsername,
		AuditStorePassword:                 cfg.AuditStorePassword,
		AuditStoreIndex:                    cfg.AuditStoreIndex,
		AuditStoreInsecureTLS:              cfg.AuditStoreInsecureTLS,
		AuditQueueBackend:                  cfg.AuditQueueBackend,
		AuditQueueEndpoint:                 cfg.AuditQueueEndpoint,
		AuditQueueTopic:                    cfg.AuditQueueTopic,
		AuditQueueExchange:                 cfg.AuditQueueExchange,
		AuditQueueRoutingKey:               cfg.AuditQueueRoutingKey,
		DatabaseMaxOpenConns:               cfg.DatabaseMaxOpenConns,
		DatabaseMaxIdleConns:               cfg.DatabaseMaxIdleConns,
		DatabaseConnMaxLifetime:            cfg.DatabaseConnMaxLifetime,
		DatabaseConnMaxIdleTime:            cfg.DatabaseConnMaxIdleTime,
		DatabaseReadAfterWriteWindow:       cfg.DatabaseReadAfterWriteWindow,
	}
}
