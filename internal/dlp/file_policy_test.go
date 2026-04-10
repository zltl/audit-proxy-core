package dlp

import "testing"

func TestFileTransferPolicyDenyOverridesAllow(t *testing.T) {
	policy := NewFileTransferPolicy(FileTransferPolicyOptions{
		AllowPaths:      []string{"exports/*"},
		AllowExtensions: []string{"csv"},
		DenyNames:       []string{"secret*"},
	})

	decision := policy.Evaluate(FileTransferMeta{
		Name: "secret-report.csv",
		Path: "exports/secret-report.csv",
	})
	if decision.Allowed {
		t.Fatalf("Evaluate(secret-report.csv) allowed, want denied")
	}
	if decision.Reason != "filename secret-report.csv matches deny rule secret*" {
		t.Fatalf("reason = %q", decision.Reason)
	}
}

func TestFileTransferPolicyRequiresEveryConfiguredAllowDimension(t *testing.T) {
	policy := NewFileTransferPolicy(FileTransferPolicyOptions{
		AllowNames:      []string{"release-*"},
		AllowExtensions: []string{"zip"},
		AllowPaths:      []string{"downloads/*"},
	})

	allowed := policy.Evaluate(FileTransferMeta{
		Name: "release-2025.zip",
		Path: "downloads/release-2025.zip",
	})
	if !allowed.Allowed {
		t.Fatalf("Evaluate(allowed) = %#v, want allowed", allowed)
	}

	blocked := policy.Evaluate(FileTransferMeta{
		Name: "release-2025.zip",
		Path: "tmp/release-2025.zip",
	})
	if blocked.Allowed {
		t.Fatalf("Evaluate(disallowed path) allowed, want denied")
	}
	if blocked.Reason != "path tmp/release-2025.zip is not in the allowlist" {
		t.Fatalf("reason = %q", blocked.Reason)
	}
}

func TestFileTransferPolicyNormalizesExtensionsAndPaths(t *testing.T) {
	policy := NewFileTransferPolicy(FileTransferPolicyOptions{
		AllowExtensions: []string{"TAR.GZ"},
		DenyPaths:       []string{"users/*/secrets/*"},
	})

	allowed := policy.Evaluate(FileTransferMeta{
		Name: "bundle.TAR.GZ",
		Path: `users\alice\packages\bundle.TAR.GZ`,
	})
	if !allowed.Allowed {
		t.Fatalf("Evaluate(bundle.TAR.GZ) = %#v, want allowed", allowed)
	}

	blocked := policy.Evaluate(FileTransferMeta{
		Name: "bundle.TAR.GZ",
		Path: `users\alice\secrets\bundle.TAR.GZ`,
	})
	if blocked.Allowed {
		t.Fatalf("Evaluate(secret path) allowed, want denied")
	}
	if blocked.Reason != "path users/alice/secrets/bundle.TAR.GZ matches deny rule users/*/secrets/*" {
		t.Fatalf("reason = %q", blocked.Reason)
	}
}

func TestFileTransferPolicyEnforcesDirectionSizeLimits(t *testing.T) {
	policy := NewFileTransferPolicy(FileTransferPolicyOptions{
		MaxUploadBytes:   10,
		MaxDownloadBytes: 4,
	})

	uploadAllowed := policy.Evaluate(FileTransferMeta{
		Direction: "upload",
		Name:      "notes.txt",
		Size:      10,
	})
	if !uploadAllowed.Allowed {
		t.Fatalf("Evaluate(upload limit edge) = %#v, want allowed", uploadAllowed)
	}

	uploadBlocked := policy.Evaluate(FileTransferMeta{
		Direction: "upload",
		Name:      "archive.tar.gz",
		Size:      11,
	})
	if uploadBlocked.Allowed {
		t.Fatalf("Evaluate(upload too large) allowed, want denied")
	}
	if uploadBlocked.Reason != "upload size 11 bytes exceeds limit 10 bytes" {
		t.Fatalf("reason = %q", uploadBlocked.Reason)
	}

	downloadBlocked := policy.Evaluate(FileTransferMeta{
		Direction: "download",
		Name:      "notes.txt",
		Size:      5,
	})
	if downloadBlocked.Allowed {
		t.Fatalf("Evaluate(download too large) allowed, want denied")
	}
	if downloadBlocked.Reason != "download size 5 bytes exceeds limit 4 bytes" {
		t.Fatalf("reason = %q", downloadBlocked.Reason)
	}
}

func TestFileTransferPolicySensitiveDetectors(t *testing.T) {
	policy := NewFileTransferPolicy(FileTransferPolicyOptions{
		SensitiveScanEnabled:    true,
		SensitiveDetectAPIKey:   true,
		SensitiveDetectCNIDCard: true,
		SensitiveMaxScanBytes:   512,
	})

	if !policy.HasSensitiveInspection() {
		t.Fatal("HasSensitiveInspection() = false, want true")
	}
	if got := policy.SensitiveMaxScanBytes(); got != 512 {
		t.Fatalf("SensitiveMaxScanBytes() = %d, want 512", got)
	}
	if len(policy.SensitivePatterns()) != 2 {
		t.Fatalf("len(SensitivePatterns()) = %d, want 2", len(policy.SensitivePatterns()))
	}

	allowed := policy.InspectContent("hello, world")
	if !allowed.Allowed {
		t.Fatalf("InspectContent(benign) = %#v, want allowed", allowed)
	}

	blockedAPIKey := policy.InspectContent(`api_key = "AKIAIOSFODNN7EXAMPLE"`)
	if blockedAPIKey.Allowed {
		t.Fatalf("InspectContent(api key) allowed, want denied")
	}
	if blockedAPIKey.Reason != "content matches API key detector" {
		t.Fatalf("reason = %q", blockedAPIKey.Reason)
	}

	blockedIDCard := policy.InspectContent("11010519491231002X")
	if blockedIDCard.Allowed {
		t.Fatalf("InspectContent(id card) allowed, want denied")
	}
	if blockedIDCard.Reason != "content matches Chinese ID card detector" {
		t.Fatalf("reason = %q", blockedIDCard.Reason)
	}
}

func TestParsePatternList(t *testing.T) {
	patterns := ParsePatternList(" *.zip, ,reports/*,.pem ")
	if len(patterns) != 3 {
		t.Fatalf("len(ParsePatternList) = %d, want 3", len(patterns))
	}
	if patterns[0] != "*.zip" || patterns[1] != "reports/*" || patterns[2] != ".pem" {
		t.Fatalf("patterns = %#v", patterns)
	}
}
