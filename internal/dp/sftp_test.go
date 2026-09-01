package dp

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"testing"
)

// recordingObserver captures what an inspector reports.
type recordingObserver struct {
	mu         sync.Mutex
	transfers  []FileTransfer
	operations []FileOperation
}

func (o *recordingObserver) FileTransferred(t FileTransfer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.transfers = append(o.transfers, t)
}

func (o *recordingObserver) FileOperated(op FileOperation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.operations = append(o.operations, op)
}

func (o *recordingObserver) transferList() []FileTransfer {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]FileTransfer(nil), o.transfers...)
}

func (o *recordingObserver) operationList() []FileOperation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]FileOperation(nil), o.operations...)
}

// scriptedPolicy refuses whatever the test tells it to.
type scriptedPolicy struct {
	denyUploads   bool
	denyDownloads bool
	denyOps       bool
}

func (p scriptedPolicy) AllowTransfer(direction TransferDirection, _ string) (bool, string) {
	if direction == TransferUpload && p.denyUploads {
		return false, "uploads are not permitted"
	}
	if direction == TransferDownload && p.denyDownloads {
		return false, "downloads are not permitted"
	}
	return true, ""
}

func (p scriptedPolicy) AllowOperation(string, string) (bool, string) {
	if p.denyOps {
		return false, "modifying files is not permitted"
	}
	return true, ""
}

// --- packet builders, so tests speak real protocol bytes -------------------

func sftpPacket(packetType byte, payload []byte) []byte {
	body := append([]byte{packetType}, payload...)
	packet := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(packet, uint32(len(body)))
	return append(packet, body...)
}

func sftpOpenPacket(id uint32, filename string, flags uint32) []byte {
	payload := appendUint32(nil, id)
	payload = appendString(payload, filename)
	payload = appendUint32(payload, flags)
	payload = appendUint32(payload, 0) // empty attrs
	return sftpPacket(sftpOpen, payload)
}

func sftpHandlePacket(id uint32, handle string) []byte {
	payload := appendUint32(nil, id)
	payload = appendString(payload, handle)
	return sftpPacket(sftpHandle, payload)
}

func sftpWritePacket(id uint32, handle string, offset uint64, data []byte) []byte {
	payload := appendUint32(nil, id)
	payload = appendString(payload, handle)
	var off [8]byte
	binary.BigEndian.PutUint64(off[:], offset)
	payload = append(payload, off[:]...)
	payload = appendUint32(payload, uint32(len(data)))
	payload = append(payload, data...)
	return sftpPacket(sftpWrite, payload)
}

func sftpReadPacket(id uint32, handle string, offset uint64, length uint32) []byte {
	payload := appendUint32(nil, id)
	payload = appendString(payload, handle)
	var off [8]byte
	binary.BigEndian.PutUint64(off[:], offset)
	payload = append(payload, off[:]...)
	payload = appendUint32(payload, length)
	return sftpPacket(sftpRead, payload)
}

func sftpDataPacket(id uint32, data []byte) []byte {
	payload := appendUint32(nil, id)
	payload = appendUint32(payload, uint32(len(data)))
	payload = append(payload, data...)
	return sftpPacket(sftpData, payload)
}

func sftpClosePacket(id uint32, handle string) []byte {
	payload := appendUint32(nil, id)
	payload = appendString(payload, handle)
	return sftpPacket(sftpClose, payload)
}

func sftpPathPacket(packetType byte, id uint32, path string) []byte {
	payload := appendUint32(nil, id)
	payload = appendString(payload, path)
	return sftpPacket(packetType, payload)
}

func sftpRenamePacket(id uint32, oldPath, newPath string) []byte {
	payload := appendUint32(nil, id)
	payload = appendString(payload, oldPath)
	payload = appendString(payload, newPath)
	return sftpPacket(sftpRename, payload)
}

// --- tests -----------------------------------------------------------------

func TestSFTPUploadIsAttributedToItsFile(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(nil, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)
	responses := newSFTPResponseFilter(inspector, &toClient, nil)

	// open for write, target returns a handle, two writes, close.
	mustWrite(t, requests, sftpOpenPacket(1, "/srv/app/deploy.tar.gz", sftpFlagWrite|sftpFlagCreat))
	mustWrite(t, responses, sftpHandlePacket(1, "h1"))
	mustWrite(t, requests, sftpWritePacket(2, "h1", 0, bytes.Repeat([]byte("a"), 4096)))
	mustWrite(t, requests, sftpWritePacket(3, "h1", 4096, bytes.Repeat([]byte("b"), 1024)))
	mustWrite(t, requests, sftpClosePacket(4, "h1"))

	transfers := observer.transferList()
	if len(transfers) != 1 {
		t.Fatalf("expected one transfer record, got %+v", transfers)
	}
	got := transfers[0]
	if got.Direction != TransferUpload {
		t.Errorf("direction = %q, want upload", got.Direction)
	}
	if got.Path != "/srv/app/deploy.tar.gz" {
		t.Errorf("path = %q; a byte-counting proxy could not report this at all", got.Path)
	}
	if got.Bytes != 5120 {
		t.Errorf("bytes = %d, want 5120", got.Bytes)
	}
	if !got.Allowed {
		t.Error("the transfer should be recorded as allowed")
	}
}

func TestSFTPDownloadCountsReturnedData(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(nil, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)
	responses := newSFTPResponseFilter(inspector, &toClient, nil)

	mustWrite(t, requests, sftpOpenPacket(1, "/etc/shadow", sftpFlagRead))
	mustWrite(t, responses, sftpHandlePacket(1, "h9"))
	// A read reply carries only the request id, so the bytes can only be
	// attributed by remembering which handle the read referred to.
	mustWrite(t, requests, sftpReadPacket(2, "h9", 0, 2048))
	mustWrite(t, responses, sftpDataPacket(2, bytes.Repeat([]byte("x"), 2048)))
	mustWrite(t, requests, sftpReadPacket(3, "h9", 2048, 512))
	mustWrite(t, responses, sftpDataPacket(3, bytes.Repeat([]byte("y"), 512)))
	mustWrite(t, requests, sftpClosePacket(4, "h9"))

	transfers := observer.transferList()
	if len(transfers) != 1 {
		t.Fatalf("expected one transfer record, got %+v", transfers)
	}
	if transfers[0].Direction != TransferDownload {
		t.Errorf("direction = %q, want download", transfers[0].Direction)
	}
	if transfers[0].Path != "/etc/shadow" {
		t.Errorf("path = %q", transfers[0].Path)
	}
	if transfers[0].Bytes != 2560 {
		t.Errorf("bytes = %d, want 2560", transfers[0].Bytes)
	}
}

func TestSFTPRefusedUploadNeverReachesTheTarget(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(scriptedPolicy{denyUploads: true}, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)

	open := sftpOpenPacket(7, "/srv/app/payload.sh", sftpFlagWrite|sftpFlagCreat)
	mustWrite(t, requests, open)

	// Blocking only counts if the open never arrives: once the target has the
	// file open, the policy is describing history rather than preventing it.
	if toUpstream.Len() != 0 {
		t.Fatalf("a refused open was forwarded to the target (%d bytes)", toUpstream.Len())
	}
	// The client must receive a failure rather than silence, or it will hang.
	if toClient.Len() == 0 {
		t.Fatal("the client was not told the open failed")
	}
	if !bytes.Contains(toClient.Bytes(), []byte("uploads are not permitted")) {
		t.Errorf("the refusal does not explain itself: %q", toClient.String())
	}

	transfers := observer.transferList()
	if len(transfers) != 1 || transfers[0].Allowed {
		t.Fatalf("a refused attempt should still be recorded: %+v", transfers)
	}
	if transfers[0].Path != "/srv/app/payload.sh" {
		t.Errorf("path = %q", transfers[0].Path)
	}
}

func TestSFTPDestructiveOperationsAreScreened(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(scriptedPolicy{denyOps: true}, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)

	// A delete moves no bytes, so a proxy that only watches data volume misses
	// it entirely — and it is among the most destructive things one can do.
	mustWrite(t, requests, sftpPathPacket(sftpRemove, 1, "/srv/app/config.yaml"))
	mustWrite(t, requests, sftpRenamePacket(2, "/srv/app/a", "/srv/app/b"))

	if toUpstream.Len() != 0 {
		t.Fatal("a refused filesystem change reached the target")
	}
	ops := observer.operationList()
	if len(ops) != 2 {
		t.Fatalf("expected both operations to be recorded, got %+v", ops)
	}
	if ops[0].Op != "remove" || ops[0].Path != "/srv/app/config.yaml" || ops[0].Allowed {
		t.Errorf("remove was recorded as %+v", ops[0])
	}
	if ops[1].Op != "rename" || ops[1].NewPath != "/srv/app/b" {
		t.Errorf("rename was recorded as %+v", ops[1])
	}
}

func TestSFTPAllowedOperationsAreForwardedAndRecorded(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(scriptedPolicy{}, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)

	remove := sftpPathPacket(sftpRemove, 1, "/tmp/scratch")
	mustWrite(t, requests, remove)

	if !bytes.Equal(toUpstream.Bytes(), remove) {
		t.Fatal("an allowed operation was not forwarded unchanged")
	}
	ops := observer.operationList()
	if len(ops) != 1 || !ops[0].Allowed {
		t.Fatalf("the operation should be recorded as allowed: %+v", ops)
	}
}

func TestSFTPHandlesSplitAndCoalescedPackets(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(nil, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)
	responses := newSFTPResponseFilter(inspector, &toClient, nil)

	// A TCP stream carries no packet boundaries: a parser that assumes one
	// write is one packet works in tests and fails against real clients.
	open := sftpOpenPacket(1, "/data/file.bin", sftpFlagWrite)
	for i := 0; i < len(open); i++ {
		mustWrite(t, requests, open[i:i+1])
	}
	mustWrite(t, responses, sftpHandlePacket(1, "h2"))

	// Several packets arriving in one write must all be processed.
	combined := append(append([]byte{},
		sftpWritePacket(2, "h2", 0, []byte("hello"))...),
		sftpClosePacket(3, "h2")...)
	mustWrite(t, requests, combined)

	transfers := observer.transferList()
	if len(transfers) != 1 {
		t.Fatalf("expected one transfer, got %+v", transfers)
	}
	if transfers[0].Path != "/data/file.bin" || transfers[0].Bytes != 5 {
		t.Fatalf("record = %+v", transfers[0])
	}
	if toUpstream.Len() != len(open)+len(combined) {
		t.Fatalf("forwarded %d bytes, want the whole stream unchanged", toUpstream.Len())
	}
}

func TestSFTPRejectsAbsurdPacketLength(t *testing.T) {
	inspector := newSFTPInspector(nil, &recordingObserver{})
	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)

	// A peer announcing an enormous packet must not make the proxy buffer
	// without limit.
	oversized := make([]byte, 4)
	binary.BigEndian.PutUint32(oversized, maxSFTPPacket+1)
	if _, err := requests.Write(oversized); err == nil {
		t.Fatal("an oversized packet length should be refused")
	}
}

func TestSFTPFlushRecordsInterruptedTransfers(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(nil, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)
	responses := newSFTPResponseFilter(inspector, &toClient, nil)

	mustWrite(t, requests, sftpOpenPacket(1, "/data/large.bin", sftpFlagWrite))
	mustWrite(t, responses, sftpHandlePacket(1, "h3"))
	mustWrite(t, requests, sftpWritePacket(2, "h3", 0, bytes.Repeat([]byte("z"), 100)))
	// No close: the session was cut off part way through.

	if len(observer.transferList()) != 0 {
		t.Fatal("a transfer should not be reported before it ends")
	}
	inspector.Flush()

	transfers := observer.transferList()
	if len(transfers) != 1 {
		t.Fatalf("an interrupted transfer left no trace: %+v", transfers)
	}
	if transfers[0].Bytes != 100 {
		t.Errorf("bytes = %d, want the partial total 100", transfers[0].Bytes)
	}
	if transfers[0].Reason == "" {
		t.Error("the record should say the transfer did not complete")
	}
}

func TestSFTPOpenForBothIsTreatedAsUpload(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(nil, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)
	responses := newSFTPResponseFilter(inspector, &toClient, nil)

	// Read-write is the direction that can change the target, so it is charged
	// as an upload rather than the more permissive download.
	mustWrite(t, requests, sftpOpenPacket(1, "/data/rw.bin", sftpFlagRead|sftpFlagWrite))
	mustWrite(t, responses, sftpHandlePacket(1, "h4"))
	mustWrite(t, requests, sftpClosePacket(2, "h4"))

	transfers := observer.transferList()
	if len(transfers) != 1 || transfers[0].Direction != TransferUpload {
		t.Fatalf("record = %+v, want an upload", transfers)
	}
}

func TestSFTPFailedOpenDoesNotLeakState(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSFTPInspector(nil, observer)

	var toUpstream, toClient bytes.Buffer
	requests := newSFTPRequestFilter(inspector, &toUpstream, &toClient, nil)
	responses := newSFTPResponseFilter(inspector, &toClient, nil)

	mustWrite(t, requests, sftpOpenPacket(1, "/no/such/file", sftpFlagRead))
	// The target refuses; there will never be a handle for this request.
	status := appendUint32(nil, 1)
	status = appendUint32(status, 2) // no such file
	status = appendString(status, "no such file")
	status = appendString(status, "")
	mustWrite(t, responses, sftpPacket(sftpStatus, status))

	inspector.mu.Lock()
	pending := len(inspector.pendingOpens)
	inspector.mu.Unlock()
	if pending != 0 {
		t.Fatalf("a failed open left %d pending entries; a long session would grow without bound", pending)
	}
	if len(observer.transferList()) != 0 {
		t.Fatal("a file that was never opened should not be reported as transferred")
	}
}

func mustWrite(t *testing.T, w interface{ Write([]byte) (int, error) }, data []byte) {
	t.Helper()
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// --- scp -------------------------------------------------------------------

func TestParseSCPCommand(t *testing.T) {
	cases := []struct {
		command string
		mode    scpMode
		path    string
		ok      bool
	}{
		{"scp -t /srv/upload", scpModeSink, "/srv/upload", true},
		{"scp -f /etc/passwd", scpModeSource, "/etc/passwd", true},
		{"scp -tr /srv/tree", scpModeSink, "/srv/tree", true},
		{"/usr/bin/scp -t /srv/upload", scpModeSink, "/srv/upload", true},
		{"scp -v -t /srv/upload", scpModeSink, "/srv/upload", true},
		{"uptime", scpModeUnknown, "", false},
		{"", scpModeUnknown, "", false},
		{"scp /local/only", scpModeUnknown, "", false},
	}
	for _, tc := range cases {
		mode, path, ok := parseSCPCommand(tc.command)
		if ok != tc.ok || mode != tc.mode || (tc.ok && path != tc.path) {
			t.Errorf("parseSCPCommand(%q) = (%v, %q, %v), want (%v, %q, %v)",
				tc.command, mode, path, ok, tc.mode, tc.path, tc.ok)
		}
	}
}

func TestSCPUploadIsRecorded(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSCPInspector(scpModeSink, "/srv/upload", nil, observer)

	var toUpstream bytes.Buffer
	filter := newSCPFilter(inspector, &toUpstream, nil)

	// The client announces the file, then sends exactly that many bytes,
	// followed by a trailing zero byte.
	mustWrite(t, filter, []byte("C0644 11 hello.txt\n"))
	mustWrite(t, filter, []byte("hello world"))
	mustWrite(t, filter, []byte{0})

	transfers := observer.transferList()
	if len(transfers) != 1 {
		t.Fatalf("expected one transfer, got %+v", transfers)
	}
	got := transfers[0]
	if got.Protocol != "scp" || got.Direction != TransferUpload {
		t.Errorf("record = %+v", got)
	}
	if got.Path != "/srv/upload/hello.txt" {
		t.Errorf("path = %q, want it qualified by the destination", got.Path)
	}
	if got.Bytes != 11 {
		t.Errorf("bytes = %d, want 11", got.Bytes)
	}
	// The stream must pass through untouched, or the transfer would corrupt.
	if !strings.Contains(toUpstream.String(), "hello world") {
		t.Error("the file content was not forwarded")
	}
}

func TestSCPHandlesContentSplitAcrossWrites(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSCPInspector(scpModeSink, "", nil, observer)
	filter := newSCPFilter(inspector, &bytes.Buffer{}, nil)

	mustWrite(t, filter, []byte("C0644 10 a.b"))
	// The control line itself is split across writes.
	mustWrite(t, filter, []byte("in\n0123"))
	mustWrite(t, filter, []byte("456789"))

	transfers := observer.transferList()
	if len(transfers) != 1 {
		t.Fatalf("expected one transfer, got %+v", transfers)
	}
	if transfers[0].Path != "a.bin" {
		t.Errorf("path = %q, want a.bin", transfers[0].Path)
	}
	if transfers[0].Bytes != 10 {
		t.Errorf("bytes = %d, want 10", transfers[0].Bytes)
	}
}

func TestSCPRecursiveTransferQualifiesNames(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSCPInspector(scpModeSink, "/srv", nil, observer)
	filter := newSCPFilter(inspector, &bytes.Buffer{}, nil)

	mustWrite(t, filter, []byte("D0755 0 app\n"))
	mustWrite(t, filter, []byte("C0644 3 run.sh\n"))
	mustWrite(t, filter, []byte("abc"))
	mustWrite(t, filter, []byte("E\n"))
	mustWrite(t, filter, []byte("C0644 2 top.txt\n"))
	mustWrite(t, filter, []byte("hi"))

	transfers := observer.transferList()
	if len(transfers) != 2 {
		t.Fatalf("expected two transfers, got %+v", transfers)
	}
	if transfers[0].Path != "/srv/app/run.sh" {
		t.Errorf("nested file path = %q", transfers[0].Path)
	}
	if transfers[1].Path != "/srv/top.txt" {
		t.Errorf("path after leaving the directory = %q", transfers[1].Path)
	}
}

func TestSCPDownloadDirection(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSCPInspector(scpModeSource, "/etc/passwd", nil, observer)
	filter := newSCPFilter(inspector, &bytes.Buffer{}, nil)

	// For a download the target sends the control lines.
	mustWrite(t, filter, []byte("C0644 5 passwd\n"))
	mustWrite(t, filter, []byte("root:"))

	transfers := observer.transferList()
	if len(transfers) != 1 || transfers[0].Direction != TransferDownload {
		t.Fatalf("record = %+v, want a download", transfers)
	}
}

func TestSCPPolicyRefusalIsRecorded(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSCPInspector(scpModeSink, "", scriptedPolicy{denyUploads: true}, observer)
	filter := newSCPFilter(inspector, &bytes.Buffer{}, nil)

	mustWrite(t, filter, []byte("C0644 3 evil.sh\n"))
	mustWrite(t, filter, []byte("abc"))

	transfers := observer.transferList()
	if len(transfers) != 1 {
		t.Fatalf("expected one record, got %+v", transfers)
	}
	if transfers[0].Allowed {
		t.Error("the transfer should be recorded as refused by policy")
	}
	if transfers[0].Reason == "" {
		t.Error("the record should carry the reason")
	}
}

func TestSCPZeroLengthFile(t *testing.T) {
	observer := &recordingObserver{}
	inspector := newSCPInspector(scpModeSink, "", nil, observer)
	filter := newSCPFilter(inspector, &bytes.Buffer{}, nil)

	// An empty file has no content between the header and the next control
	// line, which a parser waiting for bytes would never finish.
	mustWrite(t, filter, []byte("C0644 0 empty.txt\n"))
	mustWrite(t, filter, []byte("C0644 2 next.txt\n"))
	mustWrite(t, filter, []byte("hi"))

	transfers := observer.transferList()
	if len(transfers) != 2 {
		t.Fatalf("expected both files, got %+v", transfers)
	}
	if transfers[0].Path != "empty.txt" || transfers[0].Bytes != 0 {
		t.Errorf("empty file record = %+v", transfers[0])
	}
	if transfers[1].Path != "next.txt" {
		t.Errorf("second file record = %+v", transfers[1])
	}
}

func TestParseSCPFileHeader(t *testing.T) {
	cases := []struct {
		line string
		name string
		size int64
		ok   bool
	}{
		{"C0644 1234 report.pdf", "report.pdf", 1234, true},
		{"C0644 0 empty", "empty", 0, true},
		{"D0755 0 dir", "dir", 0, true},
		{"C0644 12 name with spaces.txt", "name with spaces.txt", 12, true},
		{"C0644 notanumber file", "", 0, false},
		{"C0644", "", 0, false},
		{"C0644 12 ", "", 0, false},
		{"C0644 -5 file", "", 0, false},
	}
	for _, tc := range cases {
		name, size, ok := parseSCPFileHeader(tc.line)
		if ok != tc.ok || name != tc.name || size != tc.size {
			t.Errorf("parseSCPFileHeader(%q) = (%q, %d, %v), want (%q, %d, %v)",
				tc.line, name, size, ok, tc.name, tc.size, tc.ok)
		}
	}
}
