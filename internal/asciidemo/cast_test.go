package asciidemo

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoryboardWriteAndParse(t *testing.T) {
	frames := Storyboard()
	if len(frames) < 50 {
		t.Fatalf("expected a rich storyboard, got %d frames", len(frames))
	}
	last := frames[len(frames)-1].At
	if last < 30 {
		t.Fatalf("storyboard duration = %.1fs, want >= 30s", last)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "demo.cast")
	if err := WriteCast(path, frames); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var header struct {
		Version int    `json:"version"`
		Title   string `json:"title"`
		Width   int    `json:"width"`
		Height  int    `json:"height"`
	}
	if err := json.Unmarshal(lines[0], &header); err != nil {
		t.Fatalf("header: %v", err)
	}
	if header.Version != 2 || header.Width != Width || header.Height != Height {
		t.Fatalf("unexpected header: %+v", header)
	}
	if header.Title != Title {
		t.Fatalf("title = %q", header.Title)
	}

	parsed, err := ParseOutputFrames(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != len(frames) {
		t.Fatalf("parsed frames = %d, want %d", len(parsed), len(frames))
	}

	joined := ""
	for _, f := range parsed {
		joined += f.Data
	}
	for _, needle := range []string{"audit-proxy", "COMMAND BLOCKED", "SESSION TERMINATED", "prod-db-01"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("storyboard missing %q", needle)
		}
	}
}

func TestStoryboardKeepsSingleWidthLayout(t *testing.T) {
	frames := Storyboard()
	var joined strings.Builder
	for _, f := range frames {
		joined.WriteString(f.Data)
	}
	data := joined.String()

	// Bare LF (without CR) stairs the cursor in agg/asciinema.
	for i := 0; i < len(data); i++ {
		if data[i] != '\n' {
			continue
		}
		if i == 0 || data[i-1] != '\r' {
			t.Fatalf("bare LF at offset %d (need CR+LF for stable columns)", i)
		}
	}

	// Strip CSI / OSC-ish ESC sequences, then require printable runes are ASCII.
	stripped := stripANSI(data)
	for _, r := range stripped {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			continue
		case r < 0x20 || r > 0x7e:
			t.Fatalf("non-ASCII / control rune %U in storyboard (ambiguous width breaks GIF layout)", r)
		}
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) {
			switch s[i+1] {
			case '[':
				i += 2
				for i < len(s) {
					c := s[i]
					i++
					if c >= 0x40 && c <= 0x7e {
						break
					}
				}
				continue
			case ']':
				i += 2
				for i < len(s) {
					if s[i] == '\x07' {
						i++
						break
					}
					if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
				continue
			default:
				// Other ESC sequences: skip ESC + next byte.
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func TestEmbeddedDemoCastMatchesStoryboard(t *testing.T) {
	if len(DemoCast) == 0 {
		t.Fatal("DemoCast embed is empty")
	}
	parsed, err := ParseOutputFrames(bytes.NewReader(DemoCast))
	if err != nil {
		t.Fatal(err)
	}
	story := Storyboard()
	if len(parsed) != len(story) {
		t.Fatalf("embedded frames = %d, storyboard = %d — regenerate demo.cast", len(parsed), len(story))
	}
}

func TestDripFramesHonorsSpeed(t *testing.T) {
	frames := []Frame{
		{At: 0, Data: "a"},
		{At: 1, Data: "b"},
		{At: 2, Data: "c"},
	}
	var slept time.Duration
	var out strings.Builder
	err := DripFrames(frames, DripOptions{
		Speed: 10,
		Sleep: func(d time.Duration) { slept += d },
		OnChunk: func(chunk string) error {
			out.WriteString(chunk)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "abc" {
		t.Fatalf("output = %q", out.String())
	}
	// Two gaps of 1s at 10x => 200ms total.
	if slept < 150*time.Millisecond || slept > 250*time.Millisecond {
		t.Fatalf("slept %s, want ~200ms", slept)
	}
}

func TestDripToFileUsesRecorder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.cast")
	frames := []Frame{
		{At: 0, Data: "hello"},
		{At: 0.05, Data: " world"},
	}
	if err := DripToFile(path, frames, 100); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"version":2`)) {
		t.Fatalf("missing asciicast header in %s", data)
	}
	parsed, err := ParseOutputFrames(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 {
		t.Fatalf("frames = %d", len(parsed))
	}
	if parsed[0].Data+parsed[1].Data != "hello world" {
		t.Fatalf("data = %#v", parsed)
	}
}
