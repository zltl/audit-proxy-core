package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	noColor    bool
	jsonOutput bool
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func color(c, s string) string {
	if noColor {
		return s
	}
	return c + s + colorReset
}

// printTable prints an aligned table with headers and rows.
func printTable(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i := 0; i < len(row) && i < len(widths); i++ {
			if len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}

	// Print header
	var hdr strings.Builder
	for i, h := range headers {
		if i > 0 {
			hdr.WriteString("  ")
		}
		hdr.WriteString(pad(h, widths[i]))
	}
	fmt.Println(color(colorBold, hdr.String()))

	// Print rows
	for _, row := range rows {
		var line strings.Builder
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				line.WriteString("  ")
			}
			val := ""
			if i < len(row) {
				val = row[i]
			}
			line.WriteString(pad(val, widths[i]))
		}
		fmt.Println(line.String())
	}
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// printJSON prints v as indented JSON to stdout.
func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		printError(fmt.Sprintf("failed to encode JSON: %v", err))
	}
}

// printSuccess prints a green checkmark message.
func printSuccess(msg string) {
	fmt.Println(color(colorGreen, "✓") + " " + msg)
}

// printError prints a red X message to stderr.
func printError(msg string) {
	fmt.Fprintln(os.Stderr, color(colorRed, "✗")+" "+msg)
}

// printWarning prints a yellow warning message to stderr.
func printWarning(msg string) {
	fmt.Fprintln(os.Stderr, color(colorYellow, "⚠")+" "+msg)
}

// formatTime formats an ISO 8601 / RFC 3339 timestamp into a friendly format.
func formatTime(t string) string {
	parsed, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return t
	}
	return parsed.Format("2006-01-02 15:04")
}

// formatDuration converts a duration string (e.g. "2h15m", "45m") to a
// human-readable format. If already human-readable, returns as-is.
func formatDuration(d string) string {
	dur, err := time.ParseDuration(d)
	if err != nil {
		return d
	}
	hours := int(dur.Hours())
	minutes := int(dur.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
