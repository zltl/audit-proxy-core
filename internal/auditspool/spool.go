// Package auditspool provides a durable local buffer for audit events.
//
// An audit proxy has a conflict built into it: the session must not stall
// because the control plane is slow, and the record of that session must not be
// lost because the control plane was down. Buffering in memory solves the first
// and fails the second — a crash or a restart during an outage discards exactly
// the records of the period that most needs explaining.
//
// So events are appended to a file first and only removed once the far side has
// accepted them. Delivery becomes delayed rather than lost, and the cost is one
// sequential write per event.
package auditspool

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record is one spooled entry. The payload is opaque so the spool does not need
// to know the event schema, which lets the schema change without a migration
// of anything already on disk.
type Record struct {
	Sequence int64           `json:"seq"`
	Payload  json.RawMessage `json:"event"`
}

// Options configures a Spool.
type Options struct {
	// Dir is where segment files are written.
	Dir string
	// MaxSegmentBytes is when to start a new segment. Segments are the unit of
	// deletion, so smaller ones reclaim space sooner and larger ones mean fewer
	// files.
	MaxSegmentBytes int64
	// MaxTotalBytes bounds the spool. When exceeded the oldest segments are
	// dropped: a proxy that fills its disk stops serving sessions entirely,
	// which is worse than losing the oldest records of a prolonged outage.
	MaxTotalBytes int64
	// SyncEveryWrite forces each append to durable storage. It is the
	// difference between surviving a process crash and surviving a machine
	// crash, and it costs a great deal of throughput.
	SyncEveryWrite bool
}

func (o Options) withDefaults() Options {
	if o.MaxSegmentBytes <= 0 {
		o.MaxSegmentBytes = 16 << 20
	}
	if o.MaxTotalBytes <= 0 {
		o.MaxTotalBytes = 1 << 30
	}
	return o
}

const segmentPrefix = "audit-"
const segmentSuffix = ".spool"

// Spool is an append-only, at-least-once local buffer.
type Spool struct {
	options Options

	mu       sync.Mutex
	current  *os.File
	writer   *bufio.Writer
	currentN int64
	sequence int64
	// dropped counts records discarded to stay within the size limit, so the
	// loss is visible rather than silent.
	dropped int64
}

// Open prepares the spool directory, resuming from whatever is already there.
func Open(options Options) (*Spool, error) {
	options = options.withDefaults()
	if strings.TrimSpace(options.Dir) == "" {
		return nil, errors.New("auditspool: a directory is required")
	}
	if err := os.MkdirAll(options.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("auditspool: create %s: %w", options.Dir, err)
	}

	s := &Spool{options: options}
	if err := s.openSegment(); err != nil {
		return nil, err
	}
	return s, nil
}

// Append writes one event.
func (s *Spool) Append(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sequence++
	record := Record{Sequence: s.sequence, Payload: json.RawMessage(payload)}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("auditspool: encode record: %w", err)
	}
	encoded = append(encoded, '\n')

	if s.currentN+int64(len(encoded)) > s.options.MaxSegmentBytes && s.currentN > 0 {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := s.writer.Write(encoded)
	s.currentN += int64(n)
	if err != nil {
		return fmt.Errorf("auditspool: append: %w", err)
	}
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("auditspool: flush: %w", err)
	}
	if s.options.SyncEveryWrite {
		if err := s.current.Sync(); err != nil {
			return fmt.Errorf("auditspool: sync: %w", err)
		}
	}
	return s.enforceLimitLocked()
}

// Flush pushes buffered data to the operating system.
func (s *Spool) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil {
		return nil
	}
	return s.writer.Flush()
}

// Close flushes and releases the current segment.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil
	}
	err := s.writer.Flush()
	if syncErr := s.current.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := s.current.Close(); err == nil {
		err = closeErr
	}
	s.current = nil
	s.writer = nil
	return err
}

// Batch is a set of records read from one segment, along with what to do once
// they are delivered.
type Batch struct {
	Records []Record
	// segment is the file the records came from.
	segment string
	// consumedAll reports whether the batch reached the end of the segment.
	consumedAll bool
	// offset is where reading stopped, used when a segment is partly consumed.
	offset int64
}

// Len reports how many records the batch holds.
func (b *Batch) Len() int {
	if b == nil {
		return 0
	}
	return len(b.Records)
}

// ReadBatch returns up to limit records from the oldest segment that still has
// any, without removing them. They are removed by Commit once the far side has
// accepted them, which is what makes delivery at-least-once rather than
// at-most-once.
func (s *Spool) ReadBatch(limit int) (*Batch, error) {
	if limit <= 0 {
		limit = 256
	}
	if err := s.Flush(); err != nil {
		return nil, err
	}

	segments, err := s.segments()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	currentName := ""
	if s.current != nil {
		currentName = filepath.Base(s.current.Name())
	}
	s.mu.Unlock()

	for _, segment := range segments {
		path := filepath.Join(s.options.Dir, segment)
		offset, err := readOffset(path)
		if err != nil {
			return nil, err
		}
		batch, err := readSegment(path, offset, limit)
		if err != nil {
			return nil, err
		}
		if batch.Len() > 0 {
			batch.segment = segment
			return batch, nil
		}
		// The segment is fully consumed. It can be deleted unless it is the one
		// still being written to.
		if segment != currentName {
			if err := removeSegment(path); err != nil {
				return nil, err
			}
		}
	}
	return &Batch{}, nil
}

// Commit marks a batch as delivered.
func (s *Spool) Commit(batch *Batch) error {
	if batch == nil || batch.segment == "" || batch.Len() == 0 {
		return nil
	}
	path := filepath.Join(s.options.Dir, batch.segment)
	return writeOffset(path, batch.offset)
}

// Pending reports how many bytes are waiting to be delivered, which is what an
// operator watches to tell a brief hiccup from an outage that is accumulating.
func (s *Spool) Pending() (int64, error) {
	segments, err := s.segments()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, segment := range segments {
		path := filepath.Join(s.options.Dir, segment)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		offset, err := readOffset(path)
		if err != nil {
			return 0, err
		}
		if remaining := info.Size() - offset; remaining > 0 {
			total += remaining
		}
	}
	return total, nil
}

// Dropped reports how many records were discarded to stay within the size
// limit.
func (s *Spool) Dropped() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// --------------------------------------------------------------------------
// Segments
// --------------------------------------------------------------------------

func (s *Spool) openSegment() error {
	name := fmt.Sprintf("%s%s%s", segmentPrefix,
		time.Now().UTC().Format("20060102T150405.000000000"), segmentSuffix)
	path := filepath.Join(s.options.Dir, name)

	// 0600: audit events name users, hosts, and commands.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("auditspool: open segment: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("auditspool: stat segment: %w", err)
	}
	s.current = file
	s.writer = bufio.NewWriterSize(file, 64*1024)
	s.currentN = info.Size()
	return nil
}

func (s *Spool) rotateLocked() error {
	if s.writer != nil {
		if err := s.writer.Flush(); err != nil {
			return err
		}
	}
	if s.current != nil {
		_ = s.current.Sync()
		if err := s.current.Close(); err != nil {
			return err
		}
	}
	return s.openSegment()
}

// segments lists spool files oldest first. Names embed a timestamp, so sorting
// by name sorts by age.
func (s *Spool) segments() ([]string, error) {
	entries, err := os.ReadDir(s.options.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("auditspool: list segments: %w", err)
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, segmentPrefix) || !strings.HasSuffix(name, segmentSuffix) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// enforceLimitLocked drops the oldest segments when the spool grows past its
// budget.
func (s *Spool) enforceLimitLocked() error {
	segments, err := s.segments()
	if err != nil {
		return err
	}
	var total int64
	sizes := make(map[string]int64, len(segments))
	for _, segment := range segments {
		info, err := os.Stat(filepath.Join(s.options.Dir, segment))
		if err != nil {
			continue
		}
		sizes[segment] = info.Size()
		total += info.Size()
	}
	if total <= s.options.MaxTotalBytes {
		return nil
	}

	currentName := ""
	if s.current != nil {
		currentName = filepath.Base(s.current.Name())
	}
	for _, segment := range segments {
		if total <= s.options.MaxTotalBytes {
			break
		}
		if segment == currentName {
			// Never delete the segment being written; doing so would lose the
			// events being produced right now rather than the oldest ones.
			continue
		}
		path := filepath.Join(s.options.Dir, segment)
		records, _ := countRecords(path)
		if err := removeSegment(path); err != nil {
			return err
		}
		total -= sizes[segment]
		s.dropped += records
	}
	return nil
}

func removeSegment(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("auditspool: remove segment: %w", err)
	}
	if err := os.Remove(offsetPath(path)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("auditspool: remove offset: %w", err)
	}
	return nil
}

func countRecords(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	var count int64
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for scanner.Scan() {
		if len(strings.TrimSpace(scanner.Text())) > 0 {
			count++
		}
	}
	return count, scanner.Err()
}

// readSegment reads records starting at offset.
func readSegment(path string, offset int64, limit int) (*Batch, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Batch{}, nil
		}
		return nil, fmt.Errorf("auditspool: open segment: %w", err)
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("auditspool: seek: %w", err)
	}

	batch := &Batch{offset: offset}
	reader := bufio.NewReader(file)
	for len(batch.Records) < limit {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			batch.offset += int64(len(line))
			trimmed := strings.TrimSpace(string(line))
			if trimmed != "" {
				var record Record
				if json.Unmarshal([]byte(trimmed), &record) == nil {
					batch.Records = append(batch.Records, record)
				}
				// A record that will not decode is skipped rather than blocking
				// the queue behind it forever.
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				batch.consumedAll = true
				break
			}
			return nil, fmt.Errorf("auditspool: read segment: %w", err)
		}
	}
	return batch, nil
}

func offsetPath(segmentPath string) string { return segmentPath + ".offset" }

func readOffset(segmentPath string) (int64, error) {
	raw, err := os.ReadFile(offsetPath(segmentPath))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("auditspool: read offset: %w", err)
	}
	var offset int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &offset); err != nil {
		return 0, nil
	}
	if offset < 0 {
		return 0, nil
	}
	return offset, nil
}

func writeOffset(segmentPath string, offset int64) error {
	// Written through a temporary file and renamed, so a crash mid-write leaves
	// the previous offset rather than a truncated one that would replay or skip.
	temp := offsetPath(segmentPath) + ".tmp"
	if err := os.WriteFile(temp, []byte(fmt.Sprintf("%d", offset)), 0o600); err != nil {
		return fmt.Errorf("auditspool: write offset: %w", err)
	}
	if err := os.Rename(temp, offsetPath(segmentPath)); err != nil {
		return fmt.Errorf("auditspool: commit offset: %w", err)
	}
	return nil
}
