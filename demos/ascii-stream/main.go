package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zltl/audit-proxy-core/internal/asciidemo"
)

func main() {
	fs := flag.NewFlagSet("ascii-stream", flag.ExitOnError)
	out := fs.String("out", "", "output .cast path (generate/drip)")
	speed := fs.Float64("speed", 1.0, "timing multiplier for drip (higher = faster)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: ascii-stream <generate|drip> [flags]

  generate  Write a complete asciicast from the storyboard (instant).
  drip      Append frames live via dp.Recorder (wall-clock timing).

Flags:
`)
		fs.PrintDefaults()
	}
	if len(os.Args) < 2 {
		fs.Usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	_ = fs.Parse(os.Args[2:])

	frames := asciidemo.Storyboard()
	switch cmd {
	case "generate":
		path := *out
		if path == "" {
			path = defaultDemoCastPath()
		}
		if err := asciidemo.WriteCast(path, frames); err != nil {
			fail(err)
		}
		fmt.Printf("wrote %s (%d frames, %.1fs)\n", path, len(frames), frames[len(frames)-1].At)
	case "drip":
		path := *out
		if path == "" {
			path = filepath.Join(os.TempDir(), "ascii-stream-live.cast")
		}
		fmt.Printf("dripping to %s (speed=%.2fx) — Ctrl+C to stop early\n", path, *speed)
		start := time.Now()
		if err := asciidemo.DripToFile(path, frames, *speed); err != nil {
			fail(err)
		}
		fmt.Printf("done in %s\n", time.Since(start).Round(time.Millisecond))
	default:
		fs.Usage()
		os.Exit(2)
	}
}

func defaultDemoCastPath() string {
	// Prefer writing next to the demo README when run from the repo.
	candidates := []string{
		"demos/ascii-stream/demo.cast",
		"internal/asciidemo/demo.cast",
	}
	for _, c := range candidates {
		if dir := filepath.Dir(c); dirExists(dir) {
			return c
		}
	}
	return "demo.cast"
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "ascii-stream: %v\n", err)
	os.Exit(1)
}
