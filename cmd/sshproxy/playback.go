package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"
)

func runPlay(args []string) {
	fs := flag.NewFlagSet("play", flag.ExitOnError)
	raw := fs.Bool("raw", false, "write the raw asciicast file to stdout")
	noTiming := fs.Bool("no-timing", false, "disable frame timing and print output immediately")
	includeInput := fs.Bool("include-input", false, "include client input frames in playback output")
	speed := fs.Float64("speed", 1.0, "playback speed multiplier")
	fs.BoolVar(&noColor, "no-color", noColor, "disable color output")
	fs.Parse(args)

	if fs.NArg() == 0 {
		printError("usage: sshproxy play <session-id> [--raw] [--no-timing] [--include-input] [--speed 1.0]")
		os.Exit(1)
	}
	if *speed <= 0 {
		printError("--speed must be greater than 0")
		os.Exit(1)
	}

	sessionID := fs.Arg(0)
	client := NewClient()
	resp, err := client.GetRaw("/api/v2/sessions/" + url.PathEscape(sessionID) + "/recording/download")
	if err != nil {
		printError(fmt.Sprintf("failed to download recording: %v", err))
		os.Exit(1)
	}

	if *raw {
		if _, err := os.Stdout.Write(resp.Body); err != nil {
			printError(fmt.Sprintf("failed to write recording: %v", err))
			os.Exit(1)
		}
		return
	}

	if err := playAsciicast(bytes.NewReader(resp.Body), os.Stdout, *speed, !*noTiming, *includeInput); err != nil {
		printError(fmt.Sprintf("failed to replay recording: %v", err))
		os.Exit(1)
	}
}

func playAsciicast(r io.Reader, w io.Writer, speed float64, withTiming bool, includeInput bool) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	headerSeen := false
	firstFrame := true
	var previousAt float64

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
				return fmt.Errorf("parse asciicast header: %w", err)
			}
			if header.Version != 2 {
				return fmt.Errorf("unsupported asciicast version: %d", header.Version)
			}
			headerSeen = true
			continue
		}

		var frame []json.RawMessage
		if err := json.Unmarshal(line, &frame); err != nil {
			return fmt.Errorf("parse asciicast frame: %w", err)
		}
		if len(frame) != 3 {
			return fmt.Errorf("invalid asciicast frame: expected 3 elements, got %d", len(frame))
		}

		var at float64
		var stream string
		var data string
		if err := json.Unmarshal(frame[0], &at); err != nil {
			return fmt.Errorf("parse frame timestamp: %w", err)
		}
		if err := json.Unmarshal(frame[1], &stream); err != nil {
			return fmt.Errorf("parse frame stream: %w", err)
		}
		if err := json.Unmarshal(frame[2], &data); err != nil {
			return fmt.Errorf("parse frame data: %w", err)
		}

		if withTiming && !firstFrame {
			delay := (at - previousAt) / speed
			if delay > 0 {
				time.Sleep(time.Duration(delay * float64(time.Second)))
			}
		}
		previousAt = at
		firstFrame = false

		if stream == "i" && !includeInput {
			continue
		}
		if _, err := io.WriteString(w, data); err != nil {
			return fmt.Errorf("write playback frame: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read recording: %w", err)
	}
	if !headerSeen {
		return fmt.Errorf("missing asciicast header")
	}
	return nil
}
