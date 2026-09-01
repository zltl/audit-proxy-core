// Package features defines the experimental subsystem gates shared by the
// configuration loader and the HTTP layer.
//
// A subsystem belongs here when enabling it weakens a guarantee the product is
// built on — an unaudited path, state that disappears on restart, or an
// analysis whose output looks more authoritative than its implementation is.
// Gating them means an operator opts in knowingly rather than discovering the
// caveat after an incident.
package features

import (
	"sort"
	"strings"
)

const (
	// Gateway is the protocol gateway. It dials targets with its own SSH
	// client, so traffic through it does not pass the audit data plane and is
	// not subject to session policy.
	Gateway = "gateway"

	// Collab is session collaboration. Shared sessions, chat, and four-eyes
	// approvals live only in memory and are lost on restart.
	Collab = "collab"

	// Insights is the analytics surface. Command intent, anomaly, and
	// natural-language policy endpoints are regex and keyword heuristics, not
	// models; their output must not be treated as a control.
	Insights = "insights"
)

// All lists every gate, in a stable order for diagnostics and documentation.
var All = []string{Collab, Gateway, Insights}

// Reasons explains, per feature, what the caveat is. Surfacing this in the
// error body means the operator reading it learns why the subsystem is gated.
var Reasons = map[string]string{
	Gateway:  "traffic bypasses the audit data plane and session policy",
	Collab:   "shared session state is in-memory only and is lost on restart",
	Insights: "results are keyword heuristics, not a supported control",
}

// Parse splits and normalises a comma-separated feature list. The literal "all"
// enables every gate, which is intended for development.
func Parse(raw string) []string {
	var out []string
	for _, field := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(field))
		if name == "" {
			continue
		}
		if name == "all" {
			return append([]string(nil), All...)
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Known returns every recognised gate name.
func Known() []string {
	return append([]string(nil), All...)
}

// Unknown reports names in raw that match no known gate, so a typo in
// configuration fails loudly instead of silently leaving a subsystem disabled.
func Unknown(raw string) []string {
	known := make(map[string]bool, len(All))
	for _, name := range All {
		known[name] = true
	}
	var unknown []string
	for _, name := range Parse(raw) {
		if !known[name] {
			unknown = append(unknown, name)
		}
	}
	return unknown
}
