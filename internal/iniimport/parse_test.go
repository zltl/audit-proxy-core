package iniimport

import (
	"strings"
	"testing"
)

func TestParseSectionsAndValues(t *testing.T) {
	doc, err := Parse(strings.NewReader(`
# a comment
; another comment

[server]
bind_addr = 0.0.0.0
port = 2222          # inline comment

[user:alice]
pubkey = ssh-ed25519 AAAA first
pubkey = ssh-ed25519 BBBB second
enabled = true

[policy:bob@10.0.0.1]
allow = shell, exec
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	server, ok := doc.Section("server")
	if !ok {
		t.Fatal("missing [server]")
	}
	if got := server.GetDefault("port", ""); got != "2222" {
		t.Errorf("inline comment was not stripped: %q", got)
	}

	users := doc.SectionsOfKind("user")
	if len(users) != 1 || users[0].Arg != "alice" {
		t.Fatalf("SectionsOfKind(user) = %+v", users)
	}
	keys := users[0].All("pubkey")
	if len(keys) != 2 || !strings.HasSuffix(keys[1], "second") {
		t.Fatalf("repeated keys were not all captured: %v", keys)
	}

	policies := doc.SectionsOfKind("policy")
	if len(policies) != 1 || policies[0].Arg != "bob@10.0.0.1" {
		t.Fatalf("policy section argument = %+v", policies)
	}
}

func TestParseKeepsHashInsideQuotes(t *testing.T) {
	doc, err := Parse(strings.NewReader(`
[security]
literal = "value#with#hashes"
single = 'other;semi'
trailing = plain # dropped
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	section, _ := doc.Section("security")

	if got := section.GetDefault("literal", ""); got != "value#with#hashes" {
		t.Errorf("quoted value = %q", got)
	}
	if got := section.GetDefault("single", ""); got != "other;semi" {
		t.Errorf("single-quoted value = %q", got)
	}
	if got := section.GetDefault("trailing", ""); got != "plain" {
		t.Errorf("unquoted trailing comment = %q", got)
	}
}

func TestParseLastAssignmentWins(t *testing.T) {
	doc, err := Parse(strings.NewReader("[limits]\nmax_sessions = 10\nmax_sessions = 20\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	section, _ := doc.Section("limits")
	if got := section.GetDefault("max_sessions", ""); got != "20" {
		t.Errorf("Get returned %q, want the last assignment", got)
	}
}

func TestParseHandlesMalformedInput(t *testing.T) {
	doc, err := Parse(strings.NewReader(`
orphan_key = before any section
[unterminated
[ok]
key = value
no_equals_sign
 = missing key
`))
	if err != nil {
		t.Fatalf("Parse should tolerate malformed lines: %v", err)
	}

	// The orphan assignment goes into an implicit leading section rather than
	// being lost, so an operator can see it was read.
	if len(doc.Sections) == 0 || doc.Sections[0].Name != "" {
		t.Fatalf("expected an implicit leading section, got %+v", doc.Sections)
	}
	if v, _ := doc.Sections[0].Get("orphan_key"); v != "before any section" {
		t.Errorf("orphan assignment = %q", v)
	}

	ok, found := doc.Section("ok")
	if !found {
		t.Fatal("a valid section after a malformed header was not parsed")
	}
	if v, _ := ok.Get("key"); v != "value" {
		t.Errorf("key = %q", v)
	}
	if _, present := ok.Get("no_equals_sign"); present {
		t.Error("a line without '=' should not become a key")
	}
}

func TestSectionAccessors(t *testing.T) {
	s := Section{Values: []KeyValue{{Key: "a", Value: "1"}, {Key: "B", Value: "2"}}}

	if v, ok := s.Get("b"); !ok || v != "2" {
		t.Errorf("Get should be case-insensitive: (%q, %v)", v, ok)
	}
	if v := s.GetDefault("missing", "fallback"); v != "fallback" {
		t.Errorf("GetDefault = %q", v)
	}
	if v := s.GetDefault("a", "fallback"); v != "1" {
		t.Errorf("GetDefault should prefer the present value, got %q", v)
	}
	if _, ok := s.Get("missing"); ok {
		t.Error("Get reported a missing key as present")
	}
}
