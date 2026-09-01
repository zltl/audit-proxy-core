package dp

import (
	"log"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// transferPolicy derives file-transfer rules from the capabilities the session
// was granted.
//
// The feature mask already distinguishes upload from download, so a rule that
// permits sftp but not upload is enforced per file rather than only when the
// subsystem starts. That distinction is what makes "they may fetch logs but not
// place binaries" expressible at all.
func (c *connection) transferPolicy() TransferPolicy {
	return sessionTransferPolicy{conn: c}
}

type sessionTransferPolicy struct {
	conn *connection
}

func (p sessionTransferPolicy) AllowTransfer(direction TransferDirection, filePath string) (bool, string) {
	switch direction {
	case TransferUpload:
		if !p.conn.hasFeature(store.FeatureUpload) {
			return false, "uploads are not permitted for this session"
		}
	case TransferDownload:
		if !p.conn.hasFeature(store.FeatureDownload) {
			return false, "downloads are not permitted for this session"
		}
	}
	return true, ""
}

func (p sessionTransferPolicy) AllowOperation(op, filePath string) (bool, string) {
	// Deleting, renaming, or replacing a file changes the target just as an
	// upload does, so it is charged against the same capability. A session
	// allowed only to read would otherwise be able to remove what it can see.
	switch op {
	case "remove", "rmdir", "mkdir", "rename", "setstat", "symlink":
		if !p.conn.hasFeature(store.FeatureUpload) {
			return false, "modifying files on the target is not permitted for this session"
		}
	}
	return true, ""
}

// hasFeature reports whether the session was granted a capability.
func (c *connection) hasFeature(feature store.FeatureSet) bool {
	for _, name := range feature.Names() {
		if c.features[name] {
			return true
		}
	}
	return false
}

// FileTransferred records a completed or refused file transfer.
func (c *connection) FileTransferred(transfer FileTransfer) {
	verdict := "allowed"
	if !transfer.Allowed {
		verdict = "refused"
	}
	reason := ""
	if transfer.Reason != "" {
		reason = " (" + transfer.Reason + ")"
	}
	log.Printf("dp: session %s: %s %s %s %s bytes=%d%s",
		c.sessionID, verdict, transfer.Protocol, transfer.Direction, transfer.Path,
		transfer.Bytes, reason)

	c.recordTransfer(transfer)
}

// FileOperated records a filesystem change that moved no data.
func (c *connection) FileOperated(op FileOperation) {
	verdict := "allowed"
	if !op.Allowed {
		verdict = "refused"
	}
	target := op.Path
	if op.NewPath != "" {
		target += " -> " + op.NewPath
	}
	log.Printf("dp: session %s: %s %s %s %s", c.sessionID, verdict, op.Protocol, op.Op, target)

	c.recordOperation(op)
}

// recordTransfer and recordOperation hand the records to the audit pipeline.
// They are separate from the logging above so that a deployment shipping audit
// events elsewhere does not depend on scraping the process log.
func (c *connection) recordTransfer(transfer FileTransfer) {
	c.transfersMu.Lock()
	c.transfers = append(c.transfers, transfer)
	c.transfersMu.Unlock()
	c.emitFileTransfer(transfer)
}

func (c *connection) recordOperation(op FileOperation) {
	c.transfersMu.Lock()
	c.operations = append(c.operations, op)
	c.transfersMu.Unlock()
	c.emitFileOperation(op)
}

// Transfers returns the file transfers seen on this session.
func (c *connection) Transfers() []FileTransfer {
	c.transfersMu.Lock()
	defer c.transfersMu.Unlock()
	return append([]FileTransfer(nil), c.transfers...)
}

// Operations returns the filesystem changes seen on this session.
func (c *connection) Operations() []FileOperation {
	c.transfersMu.Lock()
	defer c.transfersMu.Unlock()
	return append([]FileOperation(nil), c.operations...)
}
