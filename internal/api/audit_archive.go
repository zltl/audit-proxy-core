package api

import (
	"context"
	"io"
	"log"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

const defaultAuditArchiveSyncInterval = 5 * time.Second

type auditArchiveStore struct {
	client *minio.Client
	bucket string
	prefix string
}

func newAuditArchiveStore(cfg *Config) *auditArchiveStore {
	if cfg == nil || !cfg.AuditArchiveObjectStorageEnabled {
		return nil
	}

	endpoint, secure, err := parseObjectStorageEndpoint(
		cfg.AuditArchiveObjectStorageEndpoint,
		cfg.AuditArchiveObjectStorageUseSSL,
	)
	if err != nil {
		log.Printf("api: disable audit archive object storage: %v", err)
		return nil
	}

	client, err := newObjectStorageClient(
		endpoint,
		cfg.AuditArchiveObjectStorageAccessKey,
		cfg.AuditArchiveObjectStorageSecretKey,
		cfg.AuditArchiveObjectStorageRegion,
		secure,
	)
	if err != nil {
		log.Printf("api: disable audit archive object storage: %v", err)
		return nil
	}

	return &auditArchiveStore{
		client: client,
		bucket: strings.TrimSpace(cfg.AuditArchiveObjectStorageBucket),
		prefix: strings.Trim(strings.TrimSpace(cfg.AuditArchiveObjectStoragePrefix), "/"),
	}
}

func (s *auditArchiveStore) auditObjectKey(name string) string {
	return joinObjectKey(s.prefix, "audit", strings.Trim(filepath.ToSlash(strings.TrimSpace(name)), "/"))
}

func (s *auditArchiveStore) needsUploadAuditLog(ctx context.Context, name, path string) (bool, error) {
	if s == nil || s.client == nil {
		return false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	objectInfo, err := s.client.StatObject(ctx, s.bucket, s.auditObjectKey(name), minio.StatObjectOptions{})
	if err != nil {
		if objectStorageNotFound(err) {
			return true, nil
		}
		return false, err
	}
	if objectInfo.Size != info.Size() {
		return true, nil
	}
	if !objectInfo.LastModified.IsZero() && info.ModTime().After(objectInfo.LastModified.Add(2*time.Second)) {
		return true, nil
	}
	return false, nil
}

func (s *auditArchiveStore) uploadAuditLog(ctx context.Context, name, path string) error {
	if s == nil || s.client == nil {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	contentType := "text/plain"
	if strings.HasSuffix(strings.ToLower(name), ".jsonl") {
		contentType = "application/x-ndjson"
	}

	_, err = s.client.PutObject(
		ctx,
		s.bucket,
		s.auditObjectKey(name),
		file,
		info.Size(),
		minio.PutObjectOptions{ContentType: contentType},
	)
	return err
}

func (s *auditArchiveStore) listAuditLogNames(ctx context.Context) ([]string, error) {
	if s == nil || s.client == nil {
		return []string{}, nil
	}
	prefix := joinObjectKey(s.prefix, "audit")
	options := minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}
	var names []string
	for object := range s.client.ListObjects(ctx, s.bucket, options) {
		if object.Err != nil {
			return nil, object.Err
		}
		name := strings.TrimPrefix(object.Key, prefix)
		name = strings.TrimPrefix(name, "/")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (s *auditArchiveStore) openAuditLog(ctx context.Context, name string) (io.ReadCloser, string, error) {
	if s == nil || s.client == nil {
		return nil, "", os.ErrNotExist
	}
	key := s.auditObjectKey(name)
	object, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, "", err
	}
	if _, err := object.Stat(); err != nil {
		_ = object.Close()
		return nil, "", err
	}
	return object, pathpkg.Base(key), nil
}

// StartAuditArchiveSync mirrors append-only audit files into object storage.
func (a *API) StartAuditArchiveSync(ctx context.Context, interval time.Duration) {
	if a == nil || a.auditArchiveStore == nil || ctx == nil {
		return
	}
	if interval <= 0 {
		interval = defaultAuditArchiveSyncInterval
	}

	a.auditArchiveOnce.Do(func() {
		_ = a.syncAuditArchive(ctx)

		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_ = a.syncAuditArchive(ctx)
				}
			}
		}()
	})
}

func listAuditLogFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".log") {
			continue
		}
		paths = append(paths, filepath.Join(dir, name))
	}
	sort.Strings(paths)
	return paths, nil
}

func auditArchiveRelativeName(root, path string) string {
	if root == "" {
		return filepath.Base(path)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}

func (a *API) syncAuditArchive(ctx context.Context) error {
	if a == nil || a.auditArchiveStore == nil || a.config == nil {
		return nil
	}
	paths, err := listAuditLogFiles(a.config.AuditLogDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, path := range paths {
		if err := ensureWithinDir(a.config.AuditLogDir, path); err != nil {
			continue
		}
		name := auditArchiveRelativeName(a.config.AuditLogDir, path)
		needsUpload, err := a.auditArchiveStore.needsUploadAuditLog(ctx, name, path)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("api: check audit archive state for %s: %v", name, err)
			}
			continue
		}
		if !needsUpload {
			continue
		}
		if err := a.auditArchiveStore.uploadAuditLog(ctx, name, path); err != nil {
			log.Printf("api: archive audit log %s: %v", name, err)
		}
	}
	return nil
}

func (a *API) loadArchivedAuditEvents(ctx context.Context, localNames map[string]struct{}) ([]models.AuditEvent, error) {
	if a == nil || a.auditArchiveStore == nil {
		return []models.AuditEvent{}, nil
	}
	names, err := a.auditArchiveStore.listAuditLogNames(ctx)
	if err != nil {
		return nil, err
	}

	events := make([]models.AuditEvent, 0)
	for _, name := range names {
		if _, ok := localNames[name]; ok {
			continue
		}
		reader, _, err := a.auditArchiveStore.openAuditLog(ctx, name)
		if err != nil {
			if objectStorageNotFound(err) {
				continue
			}
			return nil, err
		}
		fileEvents, readErr := readAuditEventsFromReader(pathpkg.Join("archive", name), reader)
		_ = reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		events = append(events, fileEvents...)
	}
	return events, nil
}
