package store

import (
	"strings"
	"testing"
)

func TestFeatureSetBits(t *testing.T) {
	set := FeatureShell | FeatureSFTP

	if !set.Has(FeatureShell) || !set.Has(FeatureSFTP) {
		t.Fatalf("Has should report both bits: %s", set)
	}
	if set.Has(FeatureShell | FeatureX11) {
		t.Error("Has must require every requested bit, not any of them")
	}
	if !set.HasAny(FeatureShell | FeatureX11) {
		t.Error("HasAny should match on a single overlapping bit")
	}
	if set.Without(FeatureSFTP).Has(FeatureSFTP) {
		t.Error("Without did not clear the bit")
	}
	if !set.With(FeatureX11).Has(FeatureX11) {
		t.Error("With did not set the bit")
	}
	if FeatureNone.HasAny(FeatureAll) {
		t.Error("the empty set should overlap nothing")
	}
}

func TestParseFeatureSet(t *testing.T) {
	cases := []struct {
		input string
		want  FeatureSet
	}{
		{"shell,exec", FeatureShell | FeatureExec},
		{" Shell , SFTP ", FeatureShell | FeatureSFTP},
		{"all", FeatureAll},
		{"none", FeatureNone},
		{"", FeatureNone},
		// Legacy INI spellings must keep their meaning after import.
		{"port_forward", FeatureLocalForward | FeatureRemoteForward | FeatureDynamicForward},
		{"agent", FeatureAgentForward},
		{"file_transfer", FeatureSFTP | FeatureSCP | FeatureUpload | FeatureDownload},
	}
	for _, tc := range cases {
		got, unknown := ParseFeatureSet(tc.input)
		if len(unknown) != 0 {
			t.Errorf("ParseFeatureSet(%q) reported unknown names %v", tc.input, unknown)
		}
		if got != tc.want {
			t.Errorf("ParseFeatureSet(%q) = %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestParseFeatureSetReportsUnknownNames(t *testing.T) {
	got, unknown := ParseFeatureSet("shell,teleport,exec")
	if got != FeatureShell|FeatureExec {
		t.Errorf("known names should still parse: %s", got)
	}
	if len(unknown) != 1 || unknown[0] != "teleport" {
		t.Fatalf("unknown = %v, want [teleport]; a typo must not be silently dropped", unknown)
	}
}

func TestFeatureSetString(t *testing.T) {
	if got := FeatureAll.String(); got != "all" {
		t.Errorf("FeatureAll.String() = %q", got)
	}
	if got := FeatureNone.String(); got != "none" {
		t.Errorf("FeatureNone.String() = %q", got)
	}
	got := (FeatureShell | FeatureSFTP).String()
	if !strings.Contains(got, "shell") || !strings.Contains(got, "sftp") {
		t.Errorf("String() = %q, want it to name both features", got)
	}
	// Round-tripping keeps a stored mask readable in APIs and diffs.
	parsed, unknown := ParseFeatureSet(got)
	if len(unknown) != 0 || parsed != FeatureShell|FeatureSFTP {
		t.Errorf("String/Parse round trip failed: %q -> %s (unknown %v)", got, parsed, unknown)
	}
}

func TestFeatureByName(t *testing.T) {
	if bits, ok := FeatureByName("dynamic_forward"); !ok || bits != FeatureDynamicForward {
		t.Errorf("FeatureByName(dynamic_forward) = (%s, %v)", bits, ok)
	}
	if _, ok := FeatureByName("not-a-feature"); ok {
		t.Error("FeatureByName should reject unknown names")
	}
	if len(AllFeatureNames()) != len(featureNames) {
		t.Error("AllFeatureNames should list every declared feature")
	}
}
