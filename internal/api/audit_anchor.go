package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"

	"github.com/zltl/audit-proxy-core/internal/auditchain"
)

const defaultAuditAnchorInterval = 15 * time.Minute

type chainHead struct {
	NodeID   string
	LastHash string
	Count    int64
}

// StartAuditAnchorSync uploads tamper-evidence chain heads to WORM object storage.
func (a *API) StartAuditAnchorSync(ctx context.Context, interval time.Duration) {
	if a == nil || a.config == nil || !a.config.AuditAnchorEnabled {
		return
	}
	if interval <= 0 {
		interval = defaultAuditAnchorInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.syncAuditAnchors(ctx); err != nil {
					log.Printf("api: audit anchor sync: %v", err)
				}
			}
		}
	}()
}

func (a *API) syncAuditAnchors(ctx context.Context) error {
	if a.auditArchiveStore == nil {
		return nil
	}
	client := a.auditArchiveStore.client
	bucket := a.auditArchiveStore.bucket
	prefix := a.auditArchiveStore.prefix
	key, ok := a.auditChainKey()
	if !ok {
		return nil
	}
	entries, nodes, err := a.loadChainEntries(nil, nil)
	if err != nil {
		return err
	}
	heads := chainHeadsFromEntries(entries, nodes)
	retainDays := a.config.AuditAnchorRetentionDays
	if retainDays <= 0 {
		retainDays = 365
	}
	retainUntil := time.Now().UTC().Add(time.Duration(retainDays) * 24 * time.Hour)
	for _, head := range heads {
		anchor, err := auditchain.BuildAnchor(head.NodeID, head.LastHash, head.Count, key)
		if err != nil {
			continue
		}
		body, err := json.Marshal(anchor)
		if err != nil {
			continue
		}
		objectKey := strings.Trim(prefix, "/") + "/anchors/" + head.NodeID + "/" + anchor.Anchored.Format("20060102T150405Z") + ".json"
		_, err = client.PutObject(ctx, bucket, objectKey, bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{
			ContentType:     "application/json",
			Mode:            minio.Compliance,
			RetainUntilDate: retainUntil,
		})
		if err != nil {
			log.Printf("api: put audit anchor %s: %v", objectKey, err)
		}
	}
	return nil
}

func chainHeadsFromEntries(entries []auditchain.Entry, nodes []string) []chainHead {
	type acc struct {
		last string
		n    int64
	}
	byNode := map[string]*acc{}
	for i, e := range entries {
		node := nodes[i]
		a := byNode[node]
		if a == nil {
			a = &acc{}
			byNode[node] = a
		}
		a.n++
		if e.Hash != "" {
			a.last = e.Hash
		}
	}
	out := make([]chainHead, 0, len(byNode))
	for node, a := range byNode {
		out = append(out, chainHead{NodeID: node, LastHash: a.last, Count: a.n})
	}
	return out
}
