// Package asciidemo builds a timed ASCII “video stream” storyboard used by the
// CLI demo and the control-plane live drip / playback endpoints.
package asciidemo

import (
	"fmt"
	"strings"
)

const (
	// Width and Height size the asciicast viewport (wide enough for README / web players).
	Width  = 120
	Height = 36
	// Title is written into the asciicast header.
	Title = "Audit Proxy Core — ASCII stream demo"
)

// padCenter left-pads visible text so it appears centered in Width columns.
// ansiLen is the printable width excluding escape sequences (caller-provided).
func padCenter(s string, visible int) string {
	if visible >= Width {
		return s
	}
	pad := (Width - visible) / 2
	return strings.Repeat(" ", pad) + s
}

// Frame is one asciicast output event at a relative timestamp (seconds).
type Frame struct {
	At   float64
	Data string
}

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	green   = "\x1b[32m"
	brightG = "\x1b[92m"
	cyan    = "\x1b[36m"
	yellow  = "\x1b[33m"
	red     = "\x1b[31m"
	brightR = "\x1b[91m"
	white   = "\x1b[37m"
	clear   = "\x1b[2J\x1b[H"
	hideCur = "\x1b[?25l"
	showCur = "\x1b[?25h"
)

// Storyboard returns the full demo timeline (~70s at 1x).
func Storyboard() []Frame {
	var frames []Frame
	at := 0.0
	add := func(delay float64, data string) {
		at += delay
		frames = append(frames, Frame{At: round3(at), Data: data})
	}

	add(0.0, clear+hideCur)

	// --- Phase 1: matrix rain opener ---
	cols := make([]int, Width)
	for i := range cols {
		cols[i] = (i*7 + 3) % Height
	}
	glyphs := []rune{'0', '1', 'ﾊ', 'ﾐ', 'ﾋ', 'ｰ', 'ｳ', 'ｼ', 'ﾅ', 'ﾓ', 'ﾆ', 'ｻ', 'ﾜ', 'ﾂ', 'ｵ', 'ﾘ', 'ｱ', 'ﾎ', 'ﾃ', 'ﾏ'}
	for tick := 0; tick < 48; tick++ {
		var b strings.Builder
		b.WriteString(clear)
		b.WriteString(hideCur)
		for row := 0; row < Height-2; row++ {
			for col := 0; col < Width; col++ {
				head := cols[col]
				dist := (row - head + Height) % Height
				ch := glyphs[(col*13+row*7+tick*3)%len(glyphs)]
				switch {
				case dist == 0:
					b.WriteString(brightG + bold + string(ch) + reset)
				case dist < 4:
					b.WriteString(green + string(ch) + reset)
				case dist < 9:
					b.WriteString(dim + green + string(ch) + reset)
				default:
					b.WriteByte(' ')
				}
			}
			b.WriteByte('\n')
		}
		add(0.1, b.String())
		for i := range cols {
			cols[i] = (cols[i] + 1 + (i % 3)) % Height
		}
	}

	// --- Banner ---
	boxTop := "╔══════════════════════════════╗"
	boxMid := "║      AUDIT PROXY CORE        ║"
	boxBot := "╚══════════════════════════════╝"
	tagline := "session recording · asciicast v2 · live tail"
	banner := []string{
		"",
		padCenter(cyan+bold+boxTop+reset, len(boxTop)),
		padCenter(cyan+bold+boxMid+reset, len(boxMid)),
		padCenter(cyan+bold+boxBot+reset, len(boxBot)),
		"",
		padCenter(dim+tagline+reset, len(tagline)),
		"",
	}
	var bannerBuf strings.Builder
	bannerBuf.WriteString(clear + hideCur)
	for _, line := range banner {
		bannerBuf.WriteString(green + line + reset + "\n")
	}
	add(0.5, bannerBuf.String())
	add(1.0, "\n"+padCenter(dim+tagline+reset, len(tagline))+"\n")
	add(2.0, "\n")

	// --- Phase 2: proxy connect ---
	add(0.5, clear+showCur+cyan+bold+"audit-proxy"+reset+dim+" › "+reset+"connecting alice@bastion → prod-db-01\n")
	add(0.7, dim+"[policy]"+reset+" route matched: "+yellow+"prod-db"+reset+"  mfa=ok  recording=on\n")
	for i := 0; i < 16; i++ {
		bar := strings.Repeat("█", i) + strings.Repeat("░", 16-i)
		add(0.15, fmt.Sprintf("\r"+dim+"handshake "+reset+green+"[%s]"+reset+" %3d%%", bar, i*100/16))
	}
	add(0.35, "\r"+dim+"handshake "+reset+green+"[████████████████]"+reset+" 100%\n")
	add(0.7, fmt.Sprintf(green+"✓"+reset+" channel opened  pty %dx%d  audit stream active\n\n", Width, Height))

	prompt := green + "alice@prod-db-01" + reset + ":" + cyan + "~" + reset + "$ "

	// --- Phase 3: normal ops with typing feel ---
	typeCmd := func(cmd, output string, charDelay, afterDelay float64) {
		add(0.35, prompt)
		for _, r := range cmd {
			add(charDelay, string(r))
		}
		add(0.2, "\r\n"+output)
		if afterDelay > 0 {
			add(afterDelay, "")
		}
	}

	typeCmd("whoami", "alice\n", 0.07, 0.45)
	typeCmd("uptime", " 14:02:11 up 42 days,  3:17,  1 user,  load average: 0.08, 0.12, 0.09\n", 0.06, 0.5)
	typeCmd("ls -la /srv/app",
		"total 28\n"+
			"drwxr-xr-x  5 alice alice 4096 Mar  9 09:11 .\n"+
			"drwxr-xr-x 12 root  root  4096 Jan 14 02:40 ..\n"+
			"-rw-r-----  1 alice alice  812 Mar  9 09:11 README.md\n"+
			"drwxr-x---  3 alice alice 4096 Mar  8 18:22 bin\n"+
			"drwxr-x---  4 alice alice 4096 Mar  9 08:55 data\n",
		0.045, 0.7)

	// --- Phase 4: policy block ---
	add(0.9, prompt)
	blocked := "cat /etc/shadow"
	for _, r := range blocked {
		add(0.08, string(r))
	}
	add(0.55, "\r\n")
	ruleW := Width - 8
	if ruleW < 72 {
		ruleW = 72
	}
	rule := strings.Repeat("═", ruleW)
	add(0.35, "\n"+brightR+bold+rule+reset+"\n")
	add(0.3, brightR+bold+"  ✕  COMMAND BLOCKED  ·  policy rule: deny-sensitive-files"+reset+"\n")
	add(0.3, yellow+"  command: "+reset+"cat /etc/shadow\n")
	add(0.3, yellow+"  action:  "+reset+"deny + alert  ·  session continues under watch\n")
	add(0.3, cyan+"  audit:   "+reset+"event=command.denied id=evt_7f3a… severity=high\n")
	add(0.35, brightR+bold+rule+reset+"\n\n")
	add(0.8, dim+"# reviewer can jump here via asciicast marker"+reset+"\n")

	add(1.0, prompt)
	add(0.4, "sudo -i")
	add(0.6, "\r\n"+brightR+"✕ denied"+reset+" — privilege escalation requires JIT approval\n")
	add(1.0, dim+"jit request queued → notify on-call"+reset+"\n\n")

	// --- Phase 5: session kill / seal ---
	add(1.5, clear+hideCur)
	add(0.4, "\n\n")
	add(0.45, yellow+bold+"  ⚠  SESSION TERMINATED BY POLICY"+reset+"\n\n")
	add(0.5, "  reason:   "+red+"repeated sensitive-file access"+reset+"\n")
	add(0.4, "  actor:    threat-response / auto-kill\n")
	add(0.4, "  recording sealed → asciicast v2\n")
	add(0.7, "\n")

	seal := []string{
		"  ┌─────────────────────────────────────────────┐",
		"  │  " + green + "●" + reset + " recording.complete                       │",
		"  │  format: asciicast v2                       │",
		"  │  live tail: /ws/sessions/{id}/live          │",
		"  │  playback:  audit-proxy play · web UI         │",
		"  └─────────────────────────────────────────────┘",
	}
	for _, line := range seal {
		add(0.28, line+"\n")
	}
	add(1.4, "\n"+dim+"  demo complete — same bytes as a real audited session"+reset+"\n")
	add(0.8, showCur+"\n")

	// Drop empty data frames (used only as timing pads).
	out := frames[:0]
	for _, f := range frames {
		if f.Data == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func round3(v float64) float64 {
	return float64(int(v*1000+0.5)) / 1000
}
