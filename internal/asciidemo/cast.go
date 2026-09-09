package asciidemo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/zltl/audit-proxy-core/internal/dp"
)

// WriteCast writes an asciicast v2 file with explicit storyboard timestamps.
// The on-disk format matches internal/dp.Recorder (header + timed "o" events).
func WriteCast(path string, frames []Frame) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("asciidemo: create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("asciidemo: create cast: %w", err)
	}
	defer f.Close()
	return EncodeCast(f, frames, time.Now())
}

// EncodeCast writes asciicast v2 to w.
func EncodeCast(w io.Writer, frames []Frame, startedAt time.Time) error {
	header := map[string]interface{}{
		"version":   2,
		"width":     Width,
		"height":    Height,
		"timestamp": startedAt.Unix(),
		"title":     Title,
		"env": map[string]string{
			"TERM":  "xterm-256color",
			"SHELL": "/bin/bash",
		},
	}
	encoded, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("asciidemo: header: %w", err)
	}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return err
	}
	for _, frame := range frames {
		if frame.Data == "" {
			continue
		}
		line, err := json.Marshal([]interface{}{frame.At, "o", frame.Data})
		if err != nil {
			return fmt.Errorf("asciidemo: frame: %w", err)
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// DripOptions controls live drip timing.
type DripOptions struct {
	Speed   float64
	OnChunk func(chunk string) error
	// Sleep is overridden in tests; nil means time.Sleep.
	Sleep func(time.Duration)
}

// DripFrames invokes OnChunk for each output frame, sleeping to honor timings.
func DripFrames(frames []Frame, opts DripOptions) error {
	speed := opts.Speed
	if speed <= 0 {
		speed = 1
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	if opts.OnChunk == nil {
		return fmt.Errorf("asciidemo: OnChunk is required")
	}

	var previous float64
	first := true
	for _, frame := range frames {
		if frame.Data == "" {
			continue
		}
		if !first {
			delay := (frame.At - previous) / speed
			if delay > 0 {
				sleep(time.Duration(delay * float64(time.Second)))
			}
		}
		first = false
		previous = frame.At
		if err := opts.OnChunk(frame.Data); err != nil {
			return err
		}
	}
	return nil
}

// DripToFile appends frames into a live-writable recording using dp.Recorder,
// sleeping between frames so a live tailer can watch the stream grow.
func DripToFile(path string, frames []Frame, speed float64) error {
	if speed <= 0 {
		speed = 1
	}
	rec, err := dp.NewRecorder(dp.RecorderOptions{
		Path:      path,
		Width:     Width,
		Height:    Height,
		Title:     Title,
		StartedAt: time.Now(),
		Env: map[string]string{
			"TERM":  "xterm-256color",
			"SHELL": "/bin/bash",
		},
	})
	if err != nil {
		return err
	}
	defer rec.Close()

	return DripFrames(frames, DripOptions{
		Speed: speed,
		OnChunk: func(chunk string) error {
			rec.Output([]byte(chunk))
			return nil
		},
	})
}

// ParseOutputFrames reads asciicast v2 output ("o") frames from r.
func ParseOutputFrames(r io.Reader) ([]Frame, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	headerSeen := false
	var frames []Frame
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if !headerSeen {
			var header struct {
				Version int `json:"version"`
			}
			if err := json.Unmarshal(line, &header); err != nil {
				return nil, fmt.Errorf("asciidemo: parse header: %w", err)
			}
			if header.Version != 2 {
				return nil, fmt.Errorf("asciidemo: unsupported version %d", header.Version)
			}
			headerSeen = true
			continue
		}
		var raw []json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			return nil, fmt.Errorf("asciidemo: parse frame: %w", err)
		}
		if len(raw) != 3 {
			return nil, fmt.Errorf("asciidemo: invalid frame arity %d", len(raw))
		}
		var at float64
		var stream string
		var data string
		if err := json.Unmarshal(raw[0], &at); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw[1], &stream); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw[2], &data); err != nil {
			return nil, err
		}
		if stream != "o" || data == "" {
			continue
		}
		frames = append(frames, Frame{At: at, Data: data})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !headerSeen {
		return nil, fmt.Errorf("asciidemo: missing header")
	}
	return frames, nil
}
