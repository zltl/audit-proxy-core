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
	clear   = "\x1b[2J\x1b[H"
	hideCur = "\x1b[?25l"
	showCur = "\x1b[?25h"
	// eraseEOL clears leftover cells after a \r redraw (progress bars).
	eraseEOL = "\x1b[K"
	// nl is CR+LF. Bare LF keeps the column and stairs the cursor in agg/asciinema.
	nl = "\r\n"
)

// padCenter left-pads s so its printable width is centered in Width columns.
func padCenter(s string, visible int) string {
	if visible >= Width {
		return s
	}
	pad := (Width - visible) / 2
	return strings.Repeat(" ", pad) + s
}

// line returns text ending with CR+LF (never bare LF).
func line(s string) string { return s + nl }

// boxLine builds a single-width ASCII box row aligned with "  +----+":
// "  |" + body + padding + "|" where body+padding is exactly inner cells.
func boxLine(inner int, body string, visible int) string {
	if visible > inner {
		visible = inner
	}
	return "  |" + body + strings.Repeat(" ", inner-visible) + "|"
}

// Storyboard returns the full demo timeline (~70s at 1x).
//
// All glyphs are single-cell ASCII (or ASCII box art). Ambiguous-width Unicode
// (block elements, arrows, CJK halfwidth, emoji) makes agg wrap mid-line and
// produces the classic staircase / clipped frames in the README GIF.
func Storyboard() []Frame {
	var frames []Frame
	at := 0.0
	add := func(delay float64, data string) {
		at += delay
		frames = append(frames, Frame{At: round3(at), Data: data})
	}

	add(0.0, clear+hideCur)

	// --- Phase 1: matrix rain opener (ASCII-only, fixed Width cells/row) ---
	heads := make([]int, Width)
	for i := range heads {
		heads[i] = (i*7 + 3) % Height
	}
	glyphs := []byte("01ABCDEFGHJKLMNPQRSTUVWXYZ#*+=|/\\")
	for tick := 0; tick < 48; tick++ {
		var b strings.Builder
		b.WriteString(clear)
		b.WriteString(hideCur)
		for row := 0; row < Height-2; row++ {
			for col := 0; col < Width; col++ {
				head := heads[col]
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
			b.WriteString(nl)
		}
		add(0.1, b.String())
		for i := range heads {
			heads[i] = (heads[i] + 1 + (i % 3)) % Height
		}
	}

	// --- Banner ---
	boxTop := "+==============================+"
	boxMid := "|      AUDIT PROXY CORE        |"
	boxBot := "+==============================+"
	tagline := "session recording . asciicast v2 . live tail"
	var bannerBuf strings.Builder
	bannerBuf.WriteString(clear + hideCur)
	bannerBuf.WriteString(line(""))
	bannerBuf.WriteString(line(padCenter(cyan+bold+boxTop+reset, len(boxTop))))
	bannerBuf.WriteString(line(padCenter(cyan+bold+boxMid+reset, len(boxMid))))
	bannerBuf.WriteString(line(padCenter(cyan+bold+boxBot+reset, len(boxBot))))
	bannerBuf.WriteString(line(""))
	bannerBuf.WriteString(line(padCenter(dim+tagline+reset, len(tagline))))
	bannerBuf.WriteString(line(""))
	add(0.5, bannerBuf.String())
	add(1.0, line("")+line(padCenter(dim+tagline+reset, len(tagline))))
	add(2.0, line(""))

	// --- Phase 2: proxy connect ---
	add(0.5, clear+showCur+line(cyan+bold+"audit-proxy"+reset+dim+" > "+reset+"connecting alice@bastion -> prod-db-01"))
	add(0.7, line(dim+"[policy]"+reset+" route matched: "+yellow+"prod-db"+reset+"  mfa=ok  recording=on"))
	for i := 0; i < 16; i++ {
		bar := strings.Repeat("#", i) + strings.Repeat("-", 16-i)
		add(0.15, fmt.Sprintf("\r"+dim+"handshake "+reset+green+"[%s]"+reset+" %3d%%"+eraseEOL, bar, i*100/16))
	}
	add(0.35, "\r"+dim+"handshake "+reset+green+"[################]"+reset+" 100%"+eraseEOL+nl)
	add(0.7, line(green+"OK"+reset+fmt.Sprintf(" channel opened  pty %dx%d  audit stream active", Width, Height))+line(""))

	prompt := green + "alice@prod-db-01" + reset + ":" + cyan + "~" + reset + "$ "

	// --- Phase 3: normal ops with typing feel ---
	typeCmd := func(cmd, output string, charDelay, afterDelay float64) {
		add(0.35, prompt)
		for _, r := range cmd {
			add(charDelay, string(r))
		}
		add(0.2, nl+output)
		if afterDelay > 0 {
			add(afterDelay, "")
		}
	}

	typeCmd("whoami", line("alice"), 0.07, 0.45)
	typeCmd("uptime", line(" 14:02:11 up 42 days,  3:17,  1 user,  load average: 0.08, 0.12, 0.09"), 0.06, 0.5)
	typeCmd("ls -la /srv/app",
		line("total 28")+
			line("drwxr-xr-x  5 alice alice 4096 Mar  9 09:11 .")+
			line("drwxr-xr-x 12 root  root  4096 Jan 14 02:40 ..")+
			line("-rw-r-----  1 alice alice  812 Mar  9 09:11 README.md")+
			line("drwxr-x---  3 alice alice 4096 Mar  8 18:22 bin")+
			line("drwxr-x---  4 alice alice 4096 Mar  9 08:55 data"),
		0.045, 0.7)

	// --- Phase 4: policy block ---
	add(0.9, prompt)
	blocked := "cat /etc/shadow"
	for _, r := range blocked {
		add(0.08, string(r))
	}
	add(0.55, nl)
	ruleW := Width - 8
	if ruleW < 72 {
		ruleW = 72
	}
	rule := strings.Repeat("=", ruleW)
	add(0.35, line("")+line(brightR+bold+rule+reset))
	add(0.3, line(brightR+bold+"  X  COMMAND BLOCKED  -  policy rule: deny-sensitive-files"+reset))
	add(0.3, line(yellow+"  command: "+reset+"cat /etc/shadow"))
	add(0.3, line(yellow+"  action:  "+reset+"deny + alert  -  session continues under watch"))
	add(0.3, line(cyan+"  audit:   "+reset+"event=command.denied id=evt_7f3a... severity=high"))
	add(0.35, line(brightR+bold+rule+reset)+line(""))
	add(0.8, line(dim+"# reviewer can jump here via asciicast marker"+reset))

	add(1.0, prompt)
	add(0.4, "sudo -i")
	add(0.6, nl+line(brightR+"X denied"+reset+" - privilege escalation requires JIT approval"))
	add(1.0, line(dim+"jit request queued -> notify on-call"+reset)+line(""))

	// --- Phase 5: session kill / seal ---
	add(1.5, clear+hideCur)
	add(0.4, line("")+line(""))
	add(0.45, line(yellow+bold+"  !  SESSION TERMINATED BY POLICY"+reset)+line(""))
	add(0.5, line("  reason:   "+red+"repeated sensitive-file access"+reset))
	add(0.4, line("  actor:    threat-response / auto-kill"))
	add(0.4, line("  recording sealed -> asciicast v2"))
	add(0.7, line(""))

	const sealInner = 45
	seal := []string{
		"  +" + strings.Repeat("-", sealInner) + "+",
		boxLine(sealInner, "  "+green+"*"+reset+" recording.complete", len("  * recording.complete")),
		boxLine(sealInner, "  format: asciicast v2", len("  format: asciicast v2")),
		boxLine(sealInner, "  live tail: /ws/sessions/{id}/live", len("  live tail: /ws/sessions/{id}/live")),
		boxLine(sealInner, "  playback:  audit-proxy play / web UI", len("  playback:  audit-proxy play / web UI")),
		"  +" + strings.Repeat("-", sealInner) + "+",
	}
	for _, s := range seal {
		add(0.28, line(s))
	}
	add(1.4, line("")+line(dim+"  demo complete - same bytes as a real audited session"+reset))
	add(0.8, showCur+line(""))

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
