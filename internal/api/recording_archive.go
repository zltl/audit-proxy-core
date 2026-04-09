package api

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

const defaultRecordingArchiveSyncInterval = 5 * time.Second

func (a *API) enrichSessionRecordingPaths(sessions []models.Session) {
	for i := range sessions {
		if strings.TrimSpace(sessions[i].RecordingFile) != "" {
			continue
		}
		sessions[i].RecordingFile = a.discoverSessionRecordingPath(sessions[i].ID)
	}
}

func (a *API) discoverSessionRecordingPath(id string) string {
	if a == nil || a.config == nil || strings.TrimSpace(a.config.RecordingDir) == "" || strings.TrimSpace(id) == "" {
		return ""
	}

	entries, err := os.ReadDir(a.config.RecordingDir)
	if err != nil {
		return ""
	}

	prefix := "session_" + id + "_"
	var newestPath string
	var newestMod time.Time
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".cast") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		fullPath := filepath.Join(a.config.RecordingDir, name)
		if newestPath == "" || info.ModTime().After(newestMod) {
			newestPath = fullPath
			newestMod = info.ModTime()
		}
	}
	return newestPath
}

// StartRecordingArchiveSync mirrors local session recordings into object storage.
func (a *API) StartRecordingArchiveSync(ctx context.Context, interval time.Duration) {
	if a == nil || a.sessionMetadata == nil || a.recordingStore == nil || ctx == nil {
		return
	}
	if interval <= 0 {
		interval = defaultRecordingArchiveSyncInterval
	}
	a.recordingSyncOnce.Do(func() {
		_ = a.syncRecordingArchive(ctx)

		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_ = a.syncRecordingArchive(ctx)
				}
			}
		}()
	})
}

func (a *API) syncRecordingArchive(ctx context.Context) error {
	if a == nil || a.recordingStore == nil || a.sessionMetadata == nil {
		return nil
	}

	sessions, err := a.sessionMetadata.ListSessions()
	if err != nil {
		return err
	}
	a.enrichSessionRecordingPaths(sessions)

	for _, session := range sessions {
		recordingPath := strings.TrimSpace(session.RecordingFile)
		if recordingPath == "" {
			continue
		}
		if err := ensureWithinDir(a.config.RecordingDir, recordingPath); err != nil {
			continue
		}
		needsUpload, err := a.recordingStore.needsUploadSession(ctx, session.ID, recordingPath)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("api: check recording archive state for session %s: %v", session.ID, err)
			}
			continue
		}
		if !needsUpload {
			continue
		}
		if err := a.recordingStore.uploadSessionRecording(ctx, session.ID, recordingPath); err != nil {
			log.Printf("api: archive session recording %s: %v", session.ID, err)
		}
	}

	return nil
}
