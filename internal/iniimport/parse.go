// Package iniimport reads a legacy config.ini and turns the identity,
// authorization, and routing state it carries into database rows.
//
// The file format stays supported as a way to seed or bootstrap a deployment,
// but it stops being the source of truth: once imported, changes are made
// through the API and take effect without a reload.
package iniimport

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// Document is a parsed INI file: an ordered list of sections, each with its
// key/value pairs in file order.
type Document struct {
	Sections []Section
}

// Section is one [name] block.
type Section struct {
	Name string
	// Kind and Arg split "user:alice" into "user" and "alice"; for a plain
	// section such as [security] the Kind is the whole name and Arg is empty.
	Kind   string
	Arg    string
	Values []KeyValue
}

// KeyValue is one assignment inside a section.
type KeyValue struct {
	Key   string
	Value string
}

// Get returns the last value for a key, which matches how a repeated
// assignment overrides an earlier one.
func (s Section) Get(key string) (string, bool) {
	var (
		value string
		found bool
	)
	for _, kv := range s.Values {
		if strings.EqualFold(kv.Key, key) {
			value, found = kv.Value, true
		}
	}
	return value, found
}

// GetDefault returns the value for a key or a fallback.
func (s Section) GetDefault(key, fallback string) string {
	if v, ok := s.Get(key); ok && v != "" {
		return v
	}
	return fallback
}

// All returns every value assigned to a key, in file order. Some keys, such as
// a user's public keys, are meant to repeat.
func (s Section) All(key string) []string {
	var values []string
	for _, kv := range s.Values {
		if strings.EqualFold(kv.Key, key) {
			values = append(values, kv.Value)
		}
	}
	return values
}

// ParseFile reads and parses an INI file.
func ParseFile(path string) (*Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Parse(f)
}

// Parse reads INI content.
//
// The dialect is the one the data plane's C parser accepts: '#' and ';' start
// comments, an unquoted '#' also ends a value, and quoted values keep any '#'
// inside them.
func Parse(r io.Reader) (*Document, error) {
	doc := &Document{}
	var current *Section

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if name, ok := parseSectionHeader(line); ok {
			doc.Sections = append(doc.Sections, newSection(name))
			current = &doc.Sections[len(doc.Sections)-1]
			continue
		}
		key, value, ok := parseKeyValue(line)
		if !ok {
			continue
		}
		if current == nil {
			// Assignments before any header belong to an implicit global
			// section rather than being dropped.
			doc.Sections = append(doc.Sections, newSection(""))
			current = &doc.Sections[len(doc.Sections)-1]
		}
		current.Values = append(current.Values, KeyValue{Key: key, Value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return doc, nil
}

func newSection(name string) Section {
	kind, arg, found := strings.Cut(name, ":")
	if !found {
		kind, arg = name, ""
	}
	return Section{
		Name: name,
		Kind: strings.ToLower(strings.TrimSpace(kind)),
		Arg:  strings.TrimSpace(arg),
	}
}

// SectionsOfKind returns every section of a given kind, in file order.
func (d *Document) SectionsOfKind(kind string) []Section {
	var out []Section
	for _, s := range d.Sections {
		if s.Kind == kind {
			out = append(out, s)
		}
	}
	return out
}

// Section returns the first section with an exact name.
func (d *Document) Section(name string) (Section, bool) {
	for _, s := range d.Sections {
		if strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return Section{}, false
}

func parseSectionHeader(line string) (string, bool) {
	if !strings.HasPrefix(line, "[") {
		return "", false
	}
	end := strings.Index(line, "]")
	if end < 0 {
		return "", false
	}
	return strings.TrimSpace(line[1:end]), true
}

func parseKeyValue(line string) (key, value string, ok bool) {
	key, value, ok = strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", false
	}
	return key, stripInlineComment(strings.TrimSpace(value)), true
}

// stripInlineComment removes a trailing comment, honouring quotes so that a '#'
// inside a quoted value is kept.
func stripInlineComment(value string) string {
	var (
		inSingle bool
		inDouble bool
	)
	for i, r := range value {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#', ';':
			if !inSingle && !inDouble {
				return strings.TrimSpace(value[:i])
			}
		}
	}
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}
