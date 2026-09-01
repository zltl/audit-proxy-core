package store

import (
	"sort"
	"strings"
)

// FeatureSet is a bitmask of SSH capabilities a session may use.
//
// These are the things a policy actually needs to talk about: whether someone
// can get an interactive shell, move files, or open a tunnel. Modelling them as
// a mask keeps an access rule to one integer column and makes "allowed minus
// denied" a single operation at connect time.
type FeatureSet uint64

const (
	// FeatureShell is an interactive shell with a pty.
	FeatureShell FeatureSet = 1 << iota
	// FeatureExec is a one-shot remote command.
	FeatureExec
	// FeatureSFTP is the sftp subsystem.
	FeatureSFTP
	// FeatureSCP is the legacy scp protocol carried over exec.
	FeatureSCP
	// FeatureUpload and FeatureDownload gate transfer direction, independently
	// of which protocol carries it.
	FeatureUpload
	FeatureDownload
	// FeatureLocalForward is a client-initiated direct-tcpip channel.
	FeatureLocalForward
	// FeatureRemoteForward is a server-side listener requested with
	// tcpip-forward.
	FeatureRemoteForward
	// FeatureDynamicForward is SOCKS-style forwarding, which is local forwarding
	// with a target chosen per connection.
	FeatureDynamicForward
	// FeatureX11 is X11 display forwarding.
	FeatureX11
	// FeatureAgentForward exposes the user's agent to the upstream host, which
	// lets that host authenticate as the user elsewhere.
	FeatureAgentForward
	// FeatureSubsystem covers subsystems other than sftp.
	FeatureSubsystem
	// FeaturePTY is allocation of a pseudo-terminal.
	FeaturePTY
	// FeatureEnv is client-supplied environment variables.
	FeatureEnv
)

// FeatureNone grants nothing; FeatureAll grants every known capability.
const (
	FeatureNone FeatureSet = 0
	FeatureAll  FeatureSet = FeatureShell | FeatureExec | FeatureSFTP | FeatureSCP |
		FeatureUpload | FeatureDownload | FeatureLocalForward | FeatureRemoteForward |
		FeatureDynamicForward | FeatureX11 | FeatureAgentForward | FeatureSubsystem |
		FeaturePTY | FeatureEnv
)

// featureNames maps each bit to the name used in configuration and APIs.
var featureNames = []struct {
	bit  FeatureSet
	name string
}{
	{FeatureShell, "shell"},
	{FeatureExec, "exec"},
	{FeatureSFTP, "sftp"},
	{FeatureSCP, "scp"},
	{FeatureUpload, "upload"},
	{FeatureDownload, "download"},
	{FeatureLocalForward, "local_forward"},
	{FeatureRemoteForward, "remote_forward"},
	{FeatureDynamicForward, "dynamic_forward"},
	{FeatureX11, "x11"},
	{FeatureAgentForward, "agent_forward"},
	{FeatureSubsystem, "subsystem"},
	{FeaturePTY, "pty"},
	{FeatureEnv, "env"},
}

// featureAliases accepts the spellings used by the legacy INI policy syntax so
// that an imported configuration keeps its meaning.
var featureAliases = map[string]FeatureSet{
	"port_forward":  FeatureLocalForward | FeatureRemoteForward | FeatureDynamicForward,
	"forward":       FeatureLocalForward | FeatureRemoteForward | FeatureDynamicForward,
	"agent":         FeatureAgentForward,
	"file_transfer": FeatureSFTP | FeatureSCP | FeatureUpload | FeatureDownload,
	"sftp_list":     FeatureSFTP,
	"git":           FeatureExec,
	"git_push":      FeatureExec,
	"all":           FeatureAll,
	"none":          FeatureNone,
}

// Has reports whether every bit in want is present.
func (f FeatureSet) Has(want FeatureSet) bool { return f&want == want }

// HasAny reports whether any bit in want is present.
func (f FeatureSet) HasAny(want FeatureSet) bool { return f&want != 0 }

// With returns the set with the given bits added.
func (f FeatureSet) With(bits FeatureSet) FeatureSet { return f | bits }

// Without returns the set with the given bits removed.
func (f FeatureSet) Without(bits FeatureSet) FeatureSet { return f &^ bits }

// Names returns the feature names present in the set, sorted for stable output.
func (f FeatureSet) Names() []string {
	var names []string
	for _, entry := range featureNames {
		if f&entry.bit != 0 {
			names = append(names, entry.name)
		}
	}
	sort.Strings(names)
	return names
}

// String renders the set as a comma-separated feature list.
func (f FeatureSet) String() string {
	if f == FeatureNone {
		return "none"
	}
	if f == FeatureAll {
		return "all"
	}
	return strings.Join(f.Names(), ",")
}

// ParseFeatureSet reads a comma-separated feature list. Unknown names are
// returned so that a typo in a policy is reported rather than silently dropping
// a capability the author meant to grant or deny.
func ParseFeatureSet(raw string) (FeatureSet, []string) {
	var set FeatureSet
	var unknown []string
	for _, field := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(field))
		if name == "" {
			continue
		}
		if bits, ok := featureAliases[name]; ok {
			set |= bits
			continue
		}
		matched := false
		for _, entry := range featureNames {
			if entry.name == name {
				set |= entry.bit
				matched = true
				break
			}
		}
		if !matched {
			unknown = append(unknown, name)
		}
	}
	return set, unknown
}

// FeatureByName resolves a single feature name.
func FeatureByName(name string) (FeatureSet, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if bits, ok := featureAliases[name]; ok {
		return bits, true
	}
	for _, entry := range featureNames {
		if entry.name == name {
			return entry.bit, true
		}
	}
	return FeatureNone, false
}

// AllFeatureNames lists every known feature name.
func AllFeatureNames() []string {
	names := make([]string, 0, len(featureNames))
	for _, entry := range featureNames {
		names = append(names, entry.name)
	}
	sort.Strings(names)
	return names
}
