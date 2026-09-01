package dp

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// SCP is a much older and cruder protocol than SFTP: the client runs
// `scp -t <path>` or `scp -f <path>` on the target and the two then exchange
// control lines and raw file bytes over the same stream.
//
// It is still what a great many scripts and CI jobs use, so a proxy that only
// understands SFTP has a hole in its transfer auditing exactly where automation
// lives. Parsing the control lines is enough to recover the filename, mode, and
// declared size, which is what an audit record needs.

// scpMode is which side of the transfer the remote command implements.
type scpMode int

const (
	scpModeUnknown scpMode = iota
	// scpModeSink is `scp -t`: the target receives, so the client is uploading.
	scpModeSink
	// scpModeSource is `scp -f`: the target sends, so the client is downloading.
	scpModeSource
)

// parseSCPCommand recognises an scp invocation and which direction it runs in.
func parseSCPCommand(command string) (mode scpMode, remotePath string, ok bool) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return scpModeUnknown, "", false
	}
	base := fields[0]
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	if base != "scp" {
		return scpModeUnknown, "", false
	}

	for _, field := range fields[1:] {
		if !strings.HasPrefix(field, "-") {
			remotePath = field
			continue
		}
		// Flags are commonly bundled, as in `scp -tr`.
		for _, flag := range field[1:] {
			switch flag {
			case 't':
				mode = scpModeSink
			case 'f':
				mode = scpModeSource
			}
		}
	}
	if mode == scpModeUnknown {
		return scpModeUnknown, "", false
	}
	return mode, remotePath, true
}

// scpInspector reads the control stream of an scp transfer.
//
// Only the side that carries control lines is parsed. For an upload that is the
// client's stream; for a download it is the target's. The other side is pure
// file content and acknowledgements.
type scpInspector struct {
	mode       scpMode
	remotePath string
	policy     TransferPolicy
	observer   TransferObserver

	mu sync.Mutex
	// pending is the file currently being transferred, if any.
	pending *scpFile
	// remaining counts down the declared size, which is how the parser knows
	// where the file content ends and the next control line begins.
	remaining int64
	buf       []byte
	// directories tracks the pushd/popd of a recursive transfer so that names
	// are recorded with their full path.
	directories []string
}

type scpFile struct {
	Name  string
	Size  int64
	Bytes int64
}

func newSCPInspector(mode scpMode, remotePath string, policy TransferPolicy, observer TransferObserver) *scpInspector {
	return &scpInspector{mode: mode, remotePath: remotePath, policy: policy, observer: observer}
}

// direction reports which way files move in this transfer.
func (s *scpInspector) direction() TransferDirection {
	if s.mode == scpModeSink {
		return TransferUpload
	}
	return TransferDownload
}

// scpFilter tees the control-bearing stream through the inspector.
type scpFilter struct {
	inspector *scpInspector
	dst       io.Writer
	onForward func(int)
}

func newSCPFilter(inspector *scpInspector, dst io.Writer, onForward func(int)) *scpFilter {
	return &scpFilter{inspector: inspector, dst: dst, onForward: onForward}
}

func (f *scpFilter) Write(p []byte) (int, error) {
	f.inspector.consume(p)
	n, err := f.dst.Write(p)
	if f.onForward != nil && n > 0 {
		f.onForward(n)
	}
	return n, err
}

// consume advances the parser over a chunk of the stream.
func (s *scpInspector) consume(chunk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for len(chunk) > 0 {
		if s.remaining > 0 {
			// Inside file content: skip forward without inspecting it, but keep
			// counting so the record has a real byte total.
			take := int64(len(chunk))
			if take > s.remaining {
				take = s.remaining
			}
			if s.pending != nil {
				s.pending.Bytes += take
			}
			s.remaining -= take
			chunk = chunk[take:]
			if s.remaining == 0 {
				s.finishFileLocked()
			}
			continue
		}

		// Outside file content: accumulate until a control line completes.
		newline := bytes.IndexByte(chunk, '\n')
		if newline < 0 {
			s.buf = append(s.buf, chunk...)
			// A control line should never be long; a stream that never sends a
			// newline must not make the proxy buffer without limit.
			if len(s.buf) > 4096 {
				s.buf = s.buf[:0]
			}
			return
		}
		line := append(s.buf, chunk[:newline]...)
		s.buf = s.buf[:0]
		chunk = chunk[newline+1:]
		s.handleControlLine(string(line))
	}
}

// handleControlLine interprets one scp control message.
func (s *scpInspector) handleControlLine(line string) {
	if line == "" {
		return
	}
	switch line[0] {
	case 'C':
		// C<mode> <size> <name>
		name, size, ok := parseSCPFileHeader(line)
		if !ok {
			return
		}
		s.pending = &scpFile{Name: s.qualify(name), Size: size}
		s.remaining = size
		if size == 0 {
			s.finishFileLocked()
		}

	case 'D':
		// D<mode> 0 <name>: descend into a directory in a recursive transfer.
		if name, _, ok := parseSCPFileHeader(line); ok {
			s.directories = append(s.directories, name)
		}

	case 'E':
		// End of directory.
		if len(s.directories) > 0 {
			s.directories = s.directories[:len(s.directories)-1]
		}

	case 'T':
		// Timestamps; carries no name and needs no record.

	case 0x01, 0x02:
		// Warning or error from the peer, with the message following.
	}
}

// qualify prefixes a name with the directories a recursive transfer descended
// into, so a record names the whole path rather than just the leaf.
func (s *scpInspector) qualify(name string) string {
	if len(s.directories) == 0 {
		if s.remotePath != "" && !strings.Contains(name, "/") {
			return cleanTransferPath(s.remotePath + "/" + name)
		}
		return cleanTransferPath(name)
	}
	parts := append(append([]string{}, s.directories...), name)
	joined := strings.Join(parts, "/")
	if s.remotePath != "" {
		joined = s.remotePath + "/" + joined
	}
	return cleanTransferPath(joined)
}

func (s *scpInspector) finishFileLocked() {
	file := s.pending
	s.pending = nil
	s.remaining = 0
	if file == nil {
		return
	}

	allowed, reason := true, ""
	if s.policy != nil {
		allowed, reason = s.policy.AllowTransfer(s.direction(), file.Name)
	}
	if s.observer != nil {
		s.observer.FileTransferred(FileTransfer{
			Protocol:  "scp",
			Direction: s.direction(),
			Path:      file.Name,
			Bytes:     file.Bytes,
			Allowed:   allowed,
			Reason:    reason,
		})
	}
}

// Flush records a file that was still in flight when the session ended.
func (s *scpInspector) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return
	}
	file := s.pending
	s.pending = nil
	if s.observer != nil {
		s.observer.FileTransferred(FileTransfer{
			Protocol:  "scp",
			Direction: s.direction(),
			Path:      file.Name,
			Bytes:     file.Bytes,
			Allowed:   true,
			Reason:    "session ended before the transfer completed",
		})
	}
}

// parseSCPFileHeader reads a "C0644 1234 name" or "D0755 0 name" line.
func parseSCPFileHeader(line string) (name string, size int64, ok bool) {
	// The mode runs to the first space, then the size, then the name, which may
	// itself contain spaces.
	firstSpace := strings.IndexByte(line, ' ')
	if firstSpace < 0 {
		return "", 0, false
	}
	rest := line[firstSpace+1:]
	secondSpace := strings.IndexByte(rest, ' ')
	if secondSpace < 0 {
		return "", 0, false
	}
	size, err := strconv.ParseInt(rest[:secondSpace], 10, 64)
	if err != nil || size < 0 {
		return "", 0, false
	}
	name = strings.TrimRight(rest[secondSpace+1:], "\r")
	if name == "" {
		return "", 0, false
	}
	return name, size, true
}

// describeSCP renders a transfer for a log line.
func describeSCP(mode scpMode, remotePath string) string {
	switch mode {
	case scpModeSink:
		return fmt.Sprintf("scp upload to %s", remotePath)
	case scpModeSource:
		return fmt.Sprintf("scp download from %s", remotePath)
	default:
		return "scp"
	}
}
