package api

import (
	"context"
	"errors"
	"io"
	"log"
	"net/url"
	"os"
	pathpkg "path"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type recordingObjectStore struct {
	client *minio.Client
	bucket string
	prefix string
}

func newRecordingObjectStore(cfg *Config) *recordingObjectStore {
	if cfg == nil || !cfg.RecordingObjectStorageEnabled {
		return nil
	}

	endpoint, secure, err := parseObjectStorageEndpoint(
		cfg.RecordingObjectStorageEndpoint,
		cfg.RecordingObjectStorageUseSSL,
	)
	if err != nil {
		log.Printf("api: disable recording object storage: %v", err)
		return nil
	}

	client, err := newObjectStorageClient(
		endpoint,
		cfg.RecordingObjectStorageAccessKey,
		cfg.RecordingObjectStorageSecretKey,
		cfg.RecordingObjectStorageRegion,
		secure,
	)
	if err != nil {
		log.Printf("api: disable recording object storage: %v", err)
		return nil
	}

	return &recordingObjectStore{
		client: client,
		bucket: strings.TrimSpace(cfg.RecordingObjectStorageBucket),
		prefix: strings.Trim(strings.TrimSpace(cfg.RecordingObjectStoragePrefix), "/"),
	}
}

func parseObjectStorageEndpoint(endpoint string, secure bool) (string, bool, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", false, errors.New("missing object storage endpoint")
	}
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return "", false, err
		}
		if parsed.Host == "" {
			return "", false, errors.New("missing object storage host")
		}
		endpoint = parsed.Host
		secure = strings.EqualFold(parsed.Scheme, "https")
	}
	endpoint = strings.Trim(endpoint, "/")
	if endpoint == "" {
		return "", false, errors.New("empty object storage endpoint")
	}
	return endpoint, secure, nil
}

func newObjectStorageClient(endpoint, accessKey, secretKey, region string, secure bool) (*minio.Client, error) {
	return minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       secure,
		Region:       strings.TrimSpace(region),
		BucketLookup: minio.BucketLookupPath,
	})
}

func (s *recordingObjectStore) sessionObjectKey(id string) string {
	name := url.PathEscape(strings.TrimSpace(id)) + ".cast"
	return joinObjectKey(s.prefix, "sessions", name)
}

func joinObjectKey(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	if len(cleaned) == 0 {
		return ""
	}
	return pathpkg.Join(cleaned...)
}

func (s *recordingObjectStore) needsUploadSession(ctx context.Context, sessionID, recordingPath string) (bool, error) {
	if s == nil || s.client == nil {
		return false, nil
	}
	info, err := os.Stat(recordingPath)
	if err != nil {
		return false, err
	}

	objectInfo, err := s.client.StatObject(ctx, s.bucket, s.sessionObjectKey(sessionID), minio.StatObjectOptions{})
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

func (s *recordingObjectStore) uploadSessionRecording(ctx context.Context, sessionID, recordingPath string) error {
	if s == nil || s.client == nil {
		return nil
	}

	file, err := os.Open(recordingPath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	_, err = s.client.PutObject(
		ctx,
		s.bucket,
		s.sessionObjectKey(sessionID),
		file,
		info.Size(),
		minio.PutObjectOptions{ContentType: "application/x-asciicast"},
	)
	return err
}

func (s *recordingObjectStore) openSessionRecording(ctx context.Context, sessionID string) (io.ReadCloser, string, error) {
	if s == nil || s.client == nil {
		return nil, "", os.ErrNotExist
	}

	key := s.sessionObjectKey(sessionID)
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

func objectStorageNotFound(err error) bool {
	if err == nil {
		return false
	}
	resp := minio.ToErrorResponse(err)
	switch resp.Code {
	case "NoSuchKey", "NoSuchObject", "NotFound":
		return true
	default:
		return errors.Is(err, os.ErrNotExist)
	}
}
