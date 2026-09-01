package auditspool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newSpool(t *testing.T, options Options) *Spool {
	t.Helper()
	if options.Dir == "" {
		options.Dir = t.TempDir()
	}
	s, err := Open(options)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func appendEvents(t *testing.T, s *Spool, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		payload, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("event-%d", i)})
		if err := s.Append(payload); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
}

func TestAppendAndReadBack(t *testing.T) {
	s := newSpool(t, Options{})
	appendEvents(t, s, 3)

	batch, err := s.ReadBatch(10)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if batch.Len() != 3 {
		t.Fatalf("read %d records, want 3", batch.Len())
	}
	for i, record := range batch.Records {
		if record.Sequence != int64(i+1) {
			t.Errorf("record %d has sequence %d", i, record.Sequence)
		}
		var decoded map[string]any
		if err := json.Unmarshal(record.Payload, &decoded); err != nil {
			t.Fatalf("payload did not survive the round trip: %v", err)
		}
		if decoded["id"] != fmt.Sprintf("event-%d", i) {
			t.Errorf("payload = %v", decoded)
		}
	}
}

func TestRecordsAreRedeliveredUntilCommitted(t *testing.T) {
	s := newSpool(t, Options{})
	appendEvents(t, s, 2)

	// Reading does not consume: an event must survive a delivery attempt that
	// fails, otherwise a control-plane error loses the record.
	first, err := s.ReadBatch(10)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	again, err := s.ReadBatch(10)
	if err != nil {
		t.Fatalf("second ReadBatch: %v", err)
	}
	if again.Len() != first.Len() {
		t.Fatalf("an uncommitted batch was not offered again: %d then %d", first.Len(), again.Len())
	}

	if err := s.Commit(first); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	after, err := s.ReadBatch(10)
	if err != nil {
		t.Fatalf("ReadBatch after commit: %v", err)
	}
	if after.Len() != 0 {
		t.Fatalf("committed records were offered again: %d", after.Len())
	}
}

func TestPartialBatchesAdvanceCorrectly(t *testing.T) {
	s := newSpool(t, Options{})
	appendEvents(t, s, 5)

	batch, err := s.ReadBatch(2)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if batch.Len() != 2 {
		t.Fatalf("read %d, want the requested 2", batch.Len())
	}
	if err := s.Commit(batch); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	rest, err := s.ReadBatch(10)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if rest.Len() != 3 {
		t.Fatalf("read %d after committing 2 of 5, want 3", rest.Len())
	}
	if rest.Records[0].Sequence != 3 {
		t.Fatalf("resumed at sequence %d, want 3", rest.Records[0].Sequence)
	}
}

func TestSpoolSurvivesReopen(t *testing.T) {
	dir := t.TempDir()

	first, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	appendEvents(t, first, 4)
	batch, err := first.ReadBatch(2)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if err := first.Commit(batch); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A restart during an outage must not lose what had not been delivered;
	// that is the whole reason for writing to disk rather than buffering.
	second, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = second.Close() }()

	remaining, err := second.ReadBatch(10)
	if err != nil {
		t.Fatalf("ReadBatch after reopen: %v", err)
	}
	if remaining.Len() != 2 {
		t.Fatalf("read %d undelivered records after a restart, want 2", remaining.Len())
	}
	if remaining.Records[0].Sequence != 3 {
		t.Fatalf("resumed at sequence %d, want 3", remaining.Records[0].Sequence)
	}
}

func TestSegmentsRotateAndAreReclaimed(t *testing.T) {
	dir := t.TempDir()
	s := newSpool(t, Options{Dir: dir, MaxSegmentBytes: 256})
	appendEvents(t, s, 40)

	segments, err := s.segments()
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if len(segments) < 2 {
		t.Fatalf("expected the spool to roll over, got %d segment(s)", len(segments))
	}

	// Draining everything should reclaim the completed segments rather than
	// leaving the directory to grow forever.
	for {
		batch, err := s.ReadBatch(100)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		if batch.Len() == 0 {
			break
		}
		if err := s.Commit(batch); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}
	remaining, err := s.segments()
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if len(remaining) > 1 {
		t.Fatalf("%d segments remain after draining; consumed ones are not reclaimed", len(remaining))
	}
}

func TestOldestRecordsAreDroppedRatherThanFillingTheDisk(t *testing.T) {
	dir := t.TempDir()
	s := newSpool(t, Options{Dir: dir, MaxSegmentBytes: 256, MaxTotalBytes: 1024})

	// A proxy that fills its disk stops serving sessions altogether, which is a
	// worse outcome than losing the oldest records of a prolonged outage.
	appendEvents(t, s, 200)

	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if strings.HasSuffix(entry.Name(), segmentSuffix) {
			total += info.Size()
		}
	}
	if total > 4*1024 {
		t.Fatalf("the spool grew to %d bytes despite a 1024 byte budget", total)
	}
	if s.Dropped() == 0 {
		t.Fatal("records were discarded but the loss was not counted")
	}
}

func TestPendingReportsUndeliveredBytes(t *testing.T) {
	s := newSpool(t, Options{})

	if pending, err := s.Pending(); err != nil || pending != 0 {
		t.Fatalf("Pending on an empty spool = (%d, %v)", pending, err)
	}
	appendEvents(t, s, 5)
	pending, err := s.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if pending <= 0 {
		t.Fatal("undelivered records should be reported as pending")
	}

	batch, _ := s.ReadBatch(100)
	if err := s.Commit(batch); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if after, err := s.Pending(); err != nil || after != 0 {
		t.Fatalf("Pending after draining = (%d, %v)", after, err)
	}
}

func TestCorruptRecordDoesNotBlockTheQueue(t *testing.T) {
	dir := t.TempDir()
	s := newSpool(t, Options{Dir: dir})
	appendEvents(t, s, 1)
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Append a line that will not decode, followed by a good one. A parser that
	// stopped on the bad line would strand every event behind it.
	segments, _ := s.segments()
	path := filepath.Join(dir, segments[0])
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open segment: %v", err)
	}
	if _, err := file.WriteString("this is not json\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = file.Close()
	appendEvents(t, s, 1)

	batch, err := s.ReadBatch(10)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if batch.Len() != 2 {
		t.Fatalf("read %d records; a corrupt line blocked the ones after it", batch.Len())
	}
}

func TestOpenRequiresADirectory(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("a spool without a directory should be refused")
	}
}
