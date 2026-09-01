package dp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"sync"
)

// SFTP wire protocol, version 3 (draft-ietf-secsh-filexfer-02), which is what
// OpenSSH and every common client speak.
//
// Parsing it is what turns a file transfer from an opaque byte count into an
// audit record: which file, in which direction, how large, and whether policy
// allowed it. A proxy that only counts bytes on the channel cannot answer any
// of those, and those are the questions asked after an incident.
const (
	sftpInit     = 1
	sftpVersion  = 2
	sftpOpen     = 3
	sftpClose    = 4
	sftpRead     = 5
	sftpWrite    = 6
	sftpLstat    = 7
	sftpFstat    = 8
	sftpSetstat  = 9
	sftpFsetstat = 10
	sftpOpendir  = 11
	sftpReaddir  = 12
	sftpRemove   = 13
	sftpMkdir    = 14
	sftpRmdir    = 15
	sftpRealpath = 16
	sftpStat     = 17
	sftpRename   = 18
	sftpReadlink = 19
	sftpSymlink  = 20

	sftpStatus = 101
	sftpHandle = 102
	sftpData   = 103
	sftpName   = 104
	sftpAttrs  = 105
)

// Open flags from the same specification.
const (
	sftpFlagRead   = 0x00000001
	sftpFlagWrite  = 0x00000002
	sftpFlagAppend = 0x00000004
	sftpFlagCreat  = 0x00000008
	sftpFlagTrunc  = 0x00000010
)

// Status codes used when synthesising a refusal.
const (
	sftpStatusOK              = 0
	sftpStatusFailure         = 4
	sftpStatusPermissionDenie = 3
)

// maxSFTPPacket bounds a single packet. OpenSSH negotiates 256 KiB; the cap is
// generous but finite so a peer cannot make the proxy buffer without limit by
// announcing an enormous length.
const maxSFTPPacket = 4 << 20

// TransferDirection is which way a file moved, from the client's point of view.
type TransferDirection string

const (
	// TransferUpload is the client sending a file to the target.
	TransferUpload TransferDirection = "upload"
	// TransferDownload is the client retrieving a file from the target.
	TransferDownload TransferDirection = "download"
)

// FileTransfer is one completed file operation seen inside a transfer session.
type FileTransfer struct {
	Protocol  string
	Direction TransferDirection
	Path      string
	Bytes     int64
	// Allowed and Reason record what the transfer policy decided, so a refused
	// attempt is auditable rather than merely absent.
	Allowed bool
	Reason  string
}

// FileOperation is a non-transfer filesystem action worth recording, such as a
// delete or a rename: destructive operations that move no bytes are exactly the
// ones a byte-counting proxy misses.
type FileOperation struct {
	Protocol string
	Op       string
	Path     string
	NewPath  string
	Allowed  bool
	Reason   string
}

// TransferPolicy decides whether a file operation may proceed.
type TransferPolicy interface {
	// AllowTransfer is consulted when a file is opened, before any data moves.
	AllowTransfer(direction TransferDirection, filePath string) (allowed bool, reason string)
	// AllowOperation is consulted for filesystem changes that move no data.
	AllowOperation(op, filePath string) (allowed bool, reason string)
}

// TransferObserver receives the audit records the inspector produces.
type TransferObserver interface {
	FileTransferred(FileTransfer)
	FileOperated(FileOperation)
}

// sftpInspector tracks the state needed to describe transfers.
//
// SFTP is request/response with opaque handles: an open names a path and the
// reply returns a handle, and every subsequent read or write refers only to the
// handle. Correlating the two is the only way to attribute bytes to a filename,
// which is why both directions have to be parsed rather than just the client's.
type sftpInspector struct {
	policy   TransferPolicy
	observer TransferObserver

	mu sync.Mutex
	// pendingOpens maps a request id to the open it belongs to, until the reply
	// arrives with the handle.
	pendingOpens map[uint32]*sftpOpenRequest
	// handles maps an open handle to the file it refers to.
	handles map[string]*sftpFile
	// deniedRequests records requests the proxy refused, so the corresponding
	// reply from the target is not expected.
	deniedRequests map[uint32]bool
	// pendingReads maps a read request to its handle. A read reply carries only
	// the request id, so without this the returned bytes could not be
	// attributed to a file.
	pendingReads map[uint32]string
}

type sftpOpenRequest struct {
	Path      string
	Direction TransferDirection
}

type sftpFile struct {
	Path      string
	Direction TransferDirection
	Bytes     int64
	Allowed   bool
	Reason    string
}

func newSFTPInspector(policy TransferPolicy, observer TransferObserver) *sftpInspector {
	return &sftpInspector{
		policy:         policy,
		observer:       observer,
		pendingOpens:   make(map[uint32]*sftpOpenRequest),
		handles:        make(map[string]*sftpFile),
		deniedRequests: make(map[uint32]bool),
		pendingReads:   make(map[uint32]string),
	}
}

// sftpRequestFilter inspects packets on their way to the target and can refuse
// them.
//
// Refusing has to happen here rather than after the fact: once an open reaches
// the target the file is already accessible, and a policy that only reports
// what happened is not a policy.
type sftpRequestFilter struct {
	inspector *sftpInspector
	// dst receives packets that are allowed through.
	dst io.Writer
	// reply carries a synthesised status back to the client for refused ones.
	reply io.Writer
	// onForward accounts for bytes that actually reached the target.
	onForward func(int)

	buf []byte
}

func newSFTPRequestFilter(inspector *sftpInspector, dst, reply io.Writer, onForward func(int)) *sftpRequestFilter {
	return &sftpRequestFilter{inspector: inspector, dst: dst, reply: reply, onForward: onForward}
}

// Write buffers until whole packets are available, then decides each in turn.
func (f *sftpRequestFilter) Write(p []byte) (int, error) {
	f.buf = append(f.buf, p...)
	for {
		packet, rest, err := takeSFTPPacket(f.buf)
		if err != nil {
			return 0, err
		}
		if packet == nil {
			break
		}
		f.buf = rest
		if err := f.handlePacket(packet); err != nil {
			return 0, err
		}
	}
	// Everything was consumed into the buffer, so the caller's write succeeded
	// even when part of it is still waiting for the rest of a packet.
	return len(p), nil
}

func (f *sftpRequestFilter) handlePacket(packet []byte) error {
	decision := f.inspector.inspectRequest(packet)
	if !decision.allow {
		// The client is told the operation failed with a permission error,
		// which is what it would see from a target that refused it, and the
		// packet never reaches the target.
		if f.reply != nil {
			if _, err := f.reply.Write(buildSFTPStatus(decision.requestID,
				sftpStatusPermissionDenie, decision.reason)); err != nil {
				return err
			}
		}
		return nil
	}
	n, err := f.dst.Write(packet)
	if f.onForward != nil && n > 0 {
		f.onForward(n)
	}
	return err
}

// sftpResponseFilter watches replies so handles can be resolved to filenames
// and downloaded bytes counted.
type sftpResponseFilter struct {
	inspector *sftpInspector
	dst       io.Writer
	onForward func(int)

	buf []byte
}

func newSFTPResponseFilter(inspector *sftpInspector, dst io.Writer, onForward func(int)) *sftpResponseFilter {
	return &sftpResponseFilter{inspector: inspector, dst: dst, onForward: onForward}
}

func (f *sftpResponseFilter) Write(p []byte) (int, error) {
	f.buf = append(f.buf, p...)
	for {
		packet, rest, err := takeSFTPPacket(f.buf)
		if err != nil {
			return 0, err
		}
		if packet == nil {
			break
		}
		f.buf = rest
		f.inspector.inspectResponse(packet)
		n, err := f.dst.Write(packet)
		if f.onForward != nil && n > 0 {
			f.onForward(n)
		}
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// takeSFTPPacket splits one length-prefixed packet off the front of buf.
// It returns a nil packet when more data is needed.
func takeSFTPPacket(buf []byte) (packet, rest []byte, err error) {
	if len(buf) < 4 {
		return nil, buf, nil
	}
	length := binary.BigEndian.Uint32(buf[:4])
	if length == 0 {
		return nil, nil, errors.New("dp: sftp packet declares a zero length")
	}
	if length > maxSFTPPacket {
		return nil, nil, fmt.Errorf("dp: sftp packet of %d bytes exceeds the %d byte limit", length, maxSFTPPacket)
	}
	total := 4 + int(length)
	if len(buf) < total {
		return nil, buf, nil
	}
	// The returned slice is copied because the caller keeps appending to buf,
	// which may reallocate and invalidate an aliased slice.
	packet = make([]byte, total)
	copy(packet, buf[:total])
	return packet, buf[total:], nil
}

// requestDecision is the outcome of inspecting a client packet.
type requestDecision struct {
	allow     bool
	reason    string
	requestID uint32
}

// inspectRequest examines a client packet and decides whether to forward it.
func (i *sftpInspector) inspectRequest(packet []byte) requestDecision {
	body := packet[4:]
	if len(body) < 1 {
		return requestDecision{allow: true}
	}
	packetType := body[0]
	payload := body[1:]

	switch packetType {
	case sftpInit, sftpVersion:
		return requestDecision{allow: true}

	case sftpOpen:
		return i.inspectOpen(payload)

	case sftpWrite:
		// id, handle, offset, data
		reader := newSSHReader(payload)
		_, ok := reader.uint32()
		handle, ok2 := reader.string()
		_, ok3 := reader.uint64()
		data, ok4 := reader.string()
		if ok && ok2 && ok3 && ok4 {
			i.addBytes(handle, int64(len(data)))
		}
		return requestDecision{allow: true}

	case sftpRead:
		// id, handle, offset, length. The reply carries only the id, so the
		// handle is remembered here to attribute the bytes that come back.
		reader := newSSHReader(payload)
		requestID, ok := reader.uint32()
		handle, ok2 := reader.string()
		if ok && ok2 {
			i.noteRead(requestID, handle)
		}
		return requestDecision{allow: true}

	case sftpClose:
		reader := newSSHReader(payload)
		_, ok := reader.uint32()
		handle, ok2 := reader.string()
		if ok && ok2 {
			i.closeHandle(handle)
		}
		return requestDecision{allow: true}

	case sftpRemove, sftpRmdir:
		return i.inspectOperation(payload, operationName(packetType))

	case sftpRename:
		return i.inspectRename(payload)

	case sftpMkdir, sftpSetstat, sftpSymlink:
		return i.inspectOperation(payload, operationName(packetType))

	default:
		// Reads, directory listings, and metadata queries move no data and grant
		// nothing beyond the session's transfer capability, which was already
		// checked when the subsystem started.
		return requestDecision{allow: true}
	}
}

func (i *sftpInspector) inspectOpen(payload []byte) requestDecision {
	reader := newSSHReader(payload)
	requestID, ok := reader.uint32()
	filename, ok2 := reader.string()
	flags, ok3 := reader.uint32()
	if !ok || !ok2 || !ok3 {
		return requestDecision{allow: true}
	}

	// Opening for write is an upload; opening for read is a download. A file
	// opened for both is treated as an upload, because that is the direction
	// that changes the target.
	direction := TransferDownload
	if flags&(sftpFlagWrite|sftpFlagAppend|sftpFlagCreat|sftpFlagTrunc) != 0 {
		direction = TransferUpload
	}

	allowed, reason := true, ""
	if i.policy != nil {
		allowed, reason = i.policy.AllowTransfer(direction, cleanTransferPath(filename))
	}

	i.mu.Lock()
	if allowed {
		i.pendingOpens[requestID] = &sftpOpenRequest{Path: filename, Direction: direction}
	} else {
		i.deniedRequests[requestID] = true
	}
	i.mu.Unlock()

	if !allowed {
		// A refused open is recorded immediately: there will be no handle, no
		// close, and therefore no later opportunity to note that it happened.
		i.report(FileTransfer{
			Protocol:  "sftp",
			Direction: direction,
			Path:      filename,
			Allowed:   false,
			Reason:    reason,
		})
		return requestDecision{allow: false, reason: reason, requestID: requestID}
	}
	return requestDecision{allow: true, requestID: requestID}
}

func (i *sftpInspector) inspectOperation(payload []byte, op string) requestDecision {
	reader := newSSHReader(payload)
	requestID, ok := reader.uint32()
	target, ok2 := reader.string()
	if !ok || !ok2 {
		return requestDecision{allow: true}
	}

	allowed, reason := true, ""
	if i.policy != nil {
		allowed, reason = i.policy.AllowOperation(op, cleanTransferPath(target))
	}
	i.reportOperation(FileOperation{
		Protocol: "sftp", Op: op, Path: target, Allowed: allowed, Reason: reason,
	})
	if !allowed {
		i.mu.Lock()
		i.deniedRequests[requestID] = true
		i.mu.Unlock()
		return requestDecision{allow: false, reason: reason, requestID: requestID}
	}
	return requestDecision{allow: true, requestID: requestID}
}

func (i *sftpInspector) inspectRename(payload []byte) requestDecision {
	reader := newSSHReader(payload)
	requestID, ok := reader.uint32()
	oldPath, ok2 := reader.string()
	newPath, ok3 := reader.string()
	if !ok || !ok2 || !ok3 {
		return requestDecision{allow: true}
	}

	allowed, reason := true, ""
	if i.policy != nil {
		// A rename can defeat a name-based rule by moving a file out of the way
		// or into a permitted name, so both ends are checked.
		allowed, reason = i.policy.AllowOperation("rename", cleanTransferPath(oldPath))
		if allowed {
			allowed, reason = i.policy.AllowOperation("rename", cleanTransferPath(newPath))
		}
	}
	i.reportOperation(FileOperation{
		Protocol: "sftp", Op: "rename", Path: oldPath, NewPath: newPath,
		Allowed: allowed, Reason: reason,
	})
	if !allowed {
		i.mu.Lock()
		i.deniedRequests[requestID] = true
		i.mu.Unlock()
		return requestDecision{allow: false, reason: reason, requestID: requestID}
	}
	return requestDecision{allow: true, requestID: requestID}
}

// inspectResponse resolves handles and counts downloaded bytes.
func (i *sftpInspector) inspectResponse(packet []byte) {
	body := packet[4:]
	if len(body) < 1 {
		return
	}
	payload := body[1:]

	switch body[0] {
	case sftpHandle:
		reader := newSSHReader(payload)
		requestID, ok := reader.uint32()
		handle, ok2 := reader.string()
		if !ok || !ok2 {
			return
		}
		i.mu.Lock()
		if pending, found := i.pendingOpens[requestID]; found {
			delete(i.pendingOpens, requestID)
			i.handles[handle] = &sftpFile{
				Path:      pending.Path,
				Direction: pending.Direction,
				Allowed:   true,
			}
		}
		i.mu.Unlock()

	case sftpData:
		// Data flowing back is a download, attributed to the handle it answers.
		reader := newSSHReader(payload)
		requestID, ok := reader.uint32()
		data, ok2 := reader.string()
		if !ok || !ok2 {
			return
		}
		i.addBytesForRequest(requestID, int64(len(data)))

	case sftpStatus:
		reader := newSSHReader(payload)
		requestID, ok := reader.uint32()
		if !ok {
			return
		}
		i.mu.Lock()
		// A request that failed at the target leaves correlation entries that
		// would otherwise never be cleared.
		delete(i.pendingOpens, requestID)
		delete(i.deniedRequests, requestID)
		delete(i.pendingReads, requestID)
		i.mu.Unlock()
	}
}

// noteRead remembers which handle a read refers to.
//
// A client may have many reads outstanding at once, so this map is bounded by
// the client's window rather than by the size of the file.
func (i *sftpInspector) noteRead(requestID uint32, handle string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.pendingReads[requestID] = handle
}

func (i *sftpInspector) addBytes(handle string, n int64) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if file, ok := i.handles[handle]; ok {
		file.Bytes += n
	}
}

func (i *sftpInspector) addBytesForRequest(requestID uint32, n int64) {
	i.mu.Lock()
	defer i.mu.Unlock()
	handle, ok := i.pendingReads[requestID]
	if !ok {
		return
	}
	delete(i.pendingReads, requestID)
	if file, found := i.handles[handle]; found {
		file.Bytes += n
	}
}

func (i *sftpInspector) closeHandle(handle string) {
	i.mu.Lock()
	file, ok := i.handles[handle]
	if ok {
		delete(i.handles, handle)
	}
	i.mu.Unlock()

	if !ok {
		return
	}
	i.report(FileTransfer{
		Protocol:  "sftp",
		Direction: file.Direction,
		Path:      file.Path,
		Bytes:     file.Bytes,
		Allowed:   true,
	})
}

// Flush emits records for handles the client never closed, which happens when a
// session is cut off mid-transfer. Losing those would mean an interrupted
// exfiltration left no trace.
func (i *sftpInspector) Flush() {
	i.mu.Lock()
	files := make([]*sftpFile, 0, len(i.handles))
	for handle, file := range i.handles {
		files = append(files, file)
		delete(i.handles, handle)
	}
	i.mu.Unlock()

	for _, file := range files {
		i.report(FileTransfer{
			Protocol:  "sftp",
			Direction: file.Direction,
			Path:      file.Path,
			Bytes:     file.Bytes,
			Allowed:   true,
			Reason:    "session ended before the file was closed",
		})
	}
}

func (i *sftpInspector) report(transfer FileTransfer) {
	if i.observer != nil {
		i.observer.FileTransferred(transfer)
	}
}

func (i *sftpInspector) reportOperation(op FileOperation) {
	if i.observer != nil {
		i.observer.FileOperated(op)
	}
}

func operationName(packetType byte) string {
	switch packetType {
	case sftpRemove:
		return "remove"
	case sftpRmdir:
		return "rmdir"
	case sftpMkdir:
		return "mkdir"
	case sftpSetstat:
		return "setstat"
	case sftpSymlink:
		return "symlink"
	default:
		return "unknown"
	}
}

// buildSFTPStatus renders a status reply, used to refuse an operation without
// letting it reach the target.
func buildSFTPStatus(requestID uint32, code uint32, message string) []byte {
	// type + id + code + message + language tag
	payload := make([]byte, 0, 1+4+4+4+len(message)+4)
	payload = append(payload, sftpStatus)
	payload = appendUint32(payload, requestID)
	payload = appendUint32(payload, code)
	payload = appendString(payload, message)
	payload = appendString(payload, "")

	packet := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(packet, uint32(len(payload)))
	return append(packet, payload...)
}

func appendUint32(dst []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(dst, buf[:]...)
}

func appendString(dst []byte, s string) []byte {
	dst = appendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// sshReader decodes the length-prefixed encoding SSH and SFTP share.
type sshReader struct {
	buf []byte
	pos int
}

func newSSHReader(buf []byte) *sshReader { return &sshReader{buf: buf} }

func (r *sshReader) uint32() (uint32, bool) {
	if r.pos+4 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, true
}

func (r *sshReader) uint64() (uint64, bool) {
	if r.pos+8 > len(r.buf) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, true
}

func (r *sshReader) string() (string, bool) {
	length, ok := r.uint32()
	if !ok {
		return "", false
	}
	if r.pos+int(length) > len(r.buf) {
		return "", false
	}
	s := string(r.buf[r.pos : r.pos+int(length)])
	r.pos += int(length)
	return s, true
}

// cleanTransferPath normalises a path for policy matching so that "a/../b" and
// "b" are not treated as different files.
func cleanTransferPath(p string) string {
	if p == "" {
		return p
	}
	return path.Clean(p)
}
