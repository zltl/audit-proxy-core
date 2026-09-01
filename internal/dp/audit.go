package dp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/auditspool"
)

// Event types emitted by the data plane.
const (
	EventAuthSuccess    = "auth.success"
	EventAuthFailure    = "auth.failure"
	EventSessionStart   = "session.start"
	EventSessionEnd     = "session.end"
	EventSessionDenied  = "session.denied"
	EventChannelDenied  = "channel.denied"
	EventCommand        = "command"
	EventCommandBlocked = "command.blocked"
	EventFileTransfer   = "file.transfer"
	EventFileOperation  = "file.operation"
	EventPortForward    = "port.forward"
	EventHostKeyRefused = "hostkey.refused"
)

// auditEmitter turns session activity into records and gets them to the control
// plane.
//
// It writes to a local spool before returning, so a session never waits on the
// control plane and a record is never lost to a restart during an outage. A
// separate goroutine ships batches and only advances the spool once they are
// accepted.
type auditEmitter struct {
	nodeID string
	spool  *auditspool.Spool
	client auditReporter

	// chain links each event to the one before it. Altering or removing a
	// record then breaks the chain, which is what makes tampering detectable
	// rather than merely unlikely.
	chainMu   sync.Mutex
	prevHash  string
	chainKey  []byte
	batchSize int
}

// auditReporter is the transport that carries batches to the control plane.
type auditReporter interface {
	ReportEvents(ctx context.Context, nodeID string, events []*sshproxyv1.AuditEvent) error
}

// auditEmitterOptions configures the emitter.
type auditEmitterOptions struct {
	NodeID string
	Dir    string
	// ChainKey signs the integrity chain. Without one the chain still links
	// events by hash, but an attacker who can rewrite the log can recompute it;
	// with one they also need the key.
	ChainKey []byte
	// SyncEveryWrite trades throughput for surviving a machine crash rather
	// than only a process crash.
	SyncEveryWrite bool
	BatchSize      int
	MaxTotalBytes  int64
}

func newAuditEmitter(options auditEmitterOptions, client auditReporter) (*auditEmitter, error) {
	spool, err := auditspool.Open(auditspool.Options{
		Dir:            options.Dir,
		SyncEveryWrite: options.SyncEveryWrite,
		MaxTotalBytes:  options.MaxTotalBytes,
	})
	if err != nil {
		return nil, err
	}
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = 256
	}
	chainKey := options.ChainKey
	if len(chainKey) == 0 {
		// A per-process key still makes an attacker who tampers with the log
		// unable to recompute the chain without also compromising the running
		// process, which is a meaningfully higher bar than no key at all.
		chainKey = make([]byte, 32)
		if _, err := rand.Read(chainKey); err != nil {
			_ = spool.Close()
			return nil, err
		}
	}
	return &auditEmitter{
		nodeID:    options.NodeID,
		spool:     spool,
		client:    client,
		chainKey:  chainKey,
		batchSize: batchSize,
	}, nil
}

// Emit records one event.
//
// It returns as soon as the event is on disk. Blocking a session on the audit
// path would make the control plane's availability the proxy's availability.
func (e *auditEmitter) Emit(event *sshproxyv1.AuditEvent) {
	if e == nil || event == nil {
		return
	}
	if event.GetTimestamp() == nil {
		event.Timestamp = timestamppb.New(time.Now().UTC())
	}
	if event.GetNodeId() == "" {
		event.NodeId = e.nodeID
	}
	if event.GetId() == "" {
		event.Id = newEventID()
	}
	e.link(event)

	payload, err := protojson.Marshal(event)
	if err != nil {
		log.Printf("dp: encode audit event: %v", err)
		return
	}
	if err := e.spool.Append(payload); err != nil {
		// The event cannot be persisted. Reporting it here at least leaves it
		// in the process log rather than nowhere.
		log.Printf("dp: audit event could not be spooled (%v): %s", err, payload)
	}
}

// link computes this event's place in the integrity chain.
func (e *auditEmitter) link(event *sshproxyv1.AuditEvent) {
	e.chainMu.Lock()
	defer e.chainMu.Unlock()

	mac := hmac.New(sha256.New, e.chainKey)
	mac.Write([]byte(e.prevHash))
	mac.Write([]byte(event.GetId()))
	mac.Write([]byte(event.GetEventType()))
	mac.Write([]byte(event.GetSessionId()))
	mac.Write([]byte(event.GetUsername()))
	mac.Write([]byte(event.GetCommand()))
	if ts := event.GetTimestamp(); ts != nil {
		mac.Write([]byte(ts.AsTime().UTC().Format(time.RFC3339Nano)))
	}
	digest := hex.EncodeToString(mac.Sum(nil))

	event.PrevHash = e.prevHash
	event.IntegrityHash = digest
	e.prevHash = digest
}

// Run ships spooled events until the context ends.
func (e *auditEmitter) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// A last attempt on the way out: the events of the session that was
			// just closed are usually the interesting ones.
			e.ship(context.Background())
			return
		case <-ticker.C:
			e.ship(ctx)
		}
	}
}

// ship delivers as many batches as it can, stopping at the first failure so the
// spool is not read repeatedly while the far side is down.
func (e *auditEmitter) ship(ctx context.Context) {
	for {
		batch, err := e.spool.ReadBatch(e.batchSize)
		if err != nil {
			log.Printf("dp: read audit spool: %v", err)
			return
		}
		if batch.Len() == 0 {
			return
		}

		events := make([]*sshproxyv1.AuditEvent, 0, batch.Len())
		for _, record := range batch.Records {
			var event sshproxyv1.AuditEvent
			if err := protojson.Unmarshal(record.Payload, &event); err != nil {
				// A record that cannot be decoded would otherwise be retried
				// forever, blocking everything behind it.
				log.Printf("dp: discarding an undecodable audit record: %v", err)
				continue
			}
			events = append(events, &event)
		}

		if len(events) > 0 {
			if err := e.client.ReportEvents(ctx, e.nodeID, events); err != nil {
				// Not committing means these are offered again next time.
				log.Printf("dp: audit events could not be delivered (%v); %d record(s) remain spooled",
					err, batch.Len())
				return
			}
		}
		if err := e.spool.Commit(batch); err != nil {
			log.Printf("dp: commit audit spool: %v", err)
			return
		}
	}
}

// Close flushes and releases the spool.
func (e *auditEmitter) Close() error {
	if e == nil || e.spool == nil {
		return nil
	}
	return e.spool.Close()
}

// Pending reports how many bytes are waiting to be delivered.
func (e *auditEmitter) Pending() int64 {
	if e == nil || e.spool == nil {
		return 0
	}
	pending, err := e.spool.Pending()
	if err != nil {
		return 0
	}
	return pending
}

func newEventID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "evt-" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return "evt-" + hex.EncodeToString(buf[:])
}

// --------------------------------------------------------------------------
// Session events
// --------------------------------------------------------------------------

// baseEvent fills in the fields every event from a session shares.
func (c *connection) baseEvent(eventType string) *sshproxyv1.AuditEvent {
	return &sshproxyv1.AuditEvent{
		EventType:     eventType,
		SessionId:     c.sessionID,
		Username:      c.username,
		SourceIp:      c.sourceIP(),
		TargetHost:    c.targetHost,
		TargetPort:    int32(c.targetPort),
		UpstreamLogin: c.upstreamLogin,
		NodeId:        c.proxy.config.NodeID,
	}
}

func (c *connection) sourceIP() string {
	if c.client == nil {
		return ""
	}
	return hostOf(c.client.RemoteAddr().String())
}

func (c *connection) emit(event *sshproxyv1.AuditEvent) {
	if c.proxy != nil && c.proxy.audit != nil {
		c.proxy.audit.Emit(event)
	}
}

// emitSessionStart records that a session was established.
func (c *connection) emitSessionStart(ruleID string) {
	event := c.baseEvent(EventSessionStart)
	event.RuleId = ruleID
	event.Decision = "allow"
	c.emit(event)
}

// emitSessionEnd records how a session finished.
func (c *connection) emitSessionEnd(status, reason string) {
	event := c.baseEvent(EventSessionEnd)
	event.Decision = status
	event.Details = reason
	event.BytesIn = c.bytesIn.Load()
	event.BytesOut = c.bytesOut.Load()
	c.emit(event)
}

// emitSessionDenied records a refusal, which is at least as interesting as a
// success and would otherwise leave no trace at all.
func (c *connection) emitSessionDenied(reason string) {
	event := c.baseEvent(EventSessionDenied)
	event.Decision = "deny"
	event.Details = reason
	c.emit(event)
}

// emitChannelDenied records a channel or request refused by policy.
func (c *connection) emitChannelDenied(channelType, reason string) {
	event := c.baseEvent(EventChannelDenied)
	event.ChannelType = channelType
	event.Decision = "deny"
	event.Details = reason
	c.emit(event)
}

// emitCommand records a screened command and what policy decided about it.
func (c *connection) emitCommand(command, decision, ruleID string) {
	eventType := EventCommand
	if decision == "deny" {
		eventType = EventCommandBlocked
	}
	event := c.baseEvent(eventType)
	event.Command = command
	event.Decision = decision
	event.RuleId = ruleID
	event.ChannelType = "session"
	c.emit(event)
}

// emitFileTransfer records a file that moved, or was refused.
func (c *connection) emitFileTransfer(transfer FileTransfer) {
	event := c.baseEvent(EventFileTransfer)
	event.ChannelType = transfer.Protocol
	event.BytesIn = transfer.Bytes
	event.Decision = decisionWord(transfer.Allowed)
	event.Details = transfer.Reason
	event.FileTransfer = &sshproxyv1.FileTransferRecord{
		Direction: string(transfer.Direction),
		Path:      transfer.Path,
		Filename:  baseName(transfer.Path),
		Size:      transfer.Bytes,
		Protocol:  transfer.Protocol,
		Allowed:   transfer.Allowed,
		Reason:    transfer.Reason,
	}
	c.emit(event)
}

// emitFileOperation records a filesystem change that moved no data.
func (c *connection) emitFileOperation(op FileOperation) {
	event := c.baseEvent(EventFileOperation)
	event.ChannelType = op.Protocol
	event.Decision = decisionWord(op.Allowed)
	event.Details = op.Op + " " + op.Path
	if op.NewPath != "" {
		event.Details += " -> " + op.NewPath
	}
	if op.Reason != "" {
		event.Details += " (" + op.Reason + ")"
	}
	c.emit(event)
}

// emitPortForward records a tunnel, separately from the session's byte totals
// so that a forward is visible as its own act rather than folded into traffic.
func (c *connection) emitPortForward(kind, destHost string, destPort int, allowed bool, reason string) {
	event := c.baseEvent(EventPortForward)
	event.ChannelType = "direct-tcpip"
	event.Decision = decisionWord(allowed)
	event.Details = reason
	event.PortForward = &sshproxyv1.PortForwardRecord{
		Kind:     kind,
		DestHost: destHost,
		DestPort: int32(destPort),
	}
	c.emit(event)
}

func decisionWord(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func baseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
