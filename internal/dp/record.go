package dp

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Recorder writes a terminal session in asciicast v2 format.
//
// The format is one JSON header line followed by one JSON array per event,
// which means a recording is readable and replayable while it is still being
// written — useful when someone is watching a live session, and it means a
// crashed proxy leaves a truncated but valid recording rather than nothing.
type Recorder struct {
	mu      sync.Mutex
	file    *os.File
	writer  io.Writer
	started time.Time
	closed  bool
	path    string
	// captureInput records what the user typed as well as what they saw.
	captureInput bool
	bytesWritten int64
}

// RecorderOptions configures a recording.
type RecorderOptions struct {
	Path         string
	Width        int
	Height       int
	Title        string
	Env          map[string]string
	CaptureInput bool
	StartedAt    time.Time
}

// NewRecorder creates the file and writes the asciicast header.
func NewRecorder(opts RecorderOptions) (*Recorder, error) {
	if opts.Width <= 0 {
		opts.Width = 80
	}
	if opts.Height <= 0 {
		opts.Height = 24
	}
	if opts.StartedAt.IsZero() {
		opts.StartedAt = time.Now()
	}
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o700); err != nil {
		return nil, fmt.Errorf("dp: create recording directory: %w", err)
	}
	// 0600: a recording is a verbatim transcript of a privileged session and
	// frequently contains secrets the user typed.
	file, err := os.OpenFile(opts.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("dp: create recording: %w", err)
	}

	header := map[string]interface{}{
		"version":   2,
		"width":     opts.Width,
		"height":    opts.Height,
		"timestamp": opts.StartedAt.Unix(),
	}
	if opts.Title != "" {
		header["title"] = opts.Title
	}
	if len(opts.Env) > 0 {
		header["env"] = opts.Env
	}
	encoded, err := json.Marshal(header)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("dp: encode recording header: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("dp: write recording header: %w", err)
	}

	return &Recorder{
		file:         file,
		writer:       file,
		started:      opts.StartedAt,
		path:         opts.Path,
		captureInput: opts.CaptureInput,
	}, nil
}

// Path reports where the recording is being written.
func (r *Recorder) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Size reports how many bytes of events have been written.
func (r *Recorder) Size() int64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytesWritten
}

// Output records data the user saw.
func (r *Recorder) Output(data []byte) { r.write("o", data) }

// Input records data the user typed. Keystrokes include passwords typed at
// upstream prompts, so this is only enabled when policy asks for it.
func (r *Recorder) Input(data []byte) {
	if r == nil || !r.captureInput {
		return
	}
	r.write("i", data)
}

// Resize records a terminal size change so replay reflows correctly.
func (r *Recorder) Resize(width, height int) {
	r.write("r", []byte(fmt.Sprintf("%dx%d", width, height)))
}

// Marker records a named point in the timeline, used to mark policy decisions
// so a reviewer can jump to the moment a command was blocked or approved.
func (r *Recorder) Marker(label string) { r.write("m", []byte(label)) }

func (r *Recorder) write(kind string, data []byte) {
	if r == nil || len(data) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}

	elapsed := time.Since(r.started).Seconds()
	// json.Marshal on a []interface{} handles the escaping that terminal output
	// needs; writing the string by hand is where asciicast writers usually go
	// wrong on invalid UTF-8 and control characters.
	line, err := json.Marshal([]interface{}{elapsed, kind, string(data)})
	if err != nil {
		return
	}
	n, err := r.writer.Write(append(line, '\n'))
	if err != nil {
		// A recording that cannot be written must not take the session down,
		// but it must not silently continue either; the close path reports it.
		r.closed = true
		return
	}
	r.bytesWritten += int64(n)
}

// Close flushes and closes the recording.
func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	r.closed = true
	err := r.file.Sync()
	if closeErr := r.file.Close(); err == nil {
		err = closeErr
	}
	r.file = nil
	return err
}

// recordingWriter tees a stream into a recording as it is copied.
type recordingWriter struct {
	dst      io.Writer
	record   func([]byte)
	counter  *int64
	counterM *sync.Mutex
}

func (w recordingWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		if w.record != nil {
			w.record(p[:n])
		}
		if w.counter != nil {
			w.counterM.Lock()
			*w.counter += int64(n)
			w.counterM.Unlock()
		}
	}
	return n, err
}
