package authn

import "testing"

// Vectors from Ulrich Drepper's SHA-crypt specification, plus the hash that
// ships in this repository's example configuration. If any of these break, an
// existing deployment's users can no longer log in after migrating.
func TestVerifySHACryptKnownVectors(t *testing.T) {
	cases := []struct {
		name     string
		password string
		hash     string
	}{
		{
			name:     "sha512 spec vector",
			password: "Hello world!",
			hash: "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu" +
				"esI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
		},
		{
			name:     "sha512 with explicit rounds",
			password: "Hello world!",
			hash: "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb" +
				"HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
		},
		{
			name:     "sha256 spec vector",
			password: "Hello world!",
			hash:     "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		},
		{
			name:     "sha256 with explicit rounds",
			password: "Hello world!",
			hash:     "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
		},
		{
			name:     "example configuration hash",
			password: "test123",
			hash: "$6$saltsalt$U5d2t4MFT.Hn/auqLjcfU6R/lm2Y71FvBwABEOht/UpRtNzcFvzGl/" +
				"oU6V38pYgY8ZpicOa.0ESff5jRNylZM.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !VerifyPassword(tc.password, tc.hash) {
				t.Fatalf("the correct password was rejected for %s", tc.hash)
			}
			if VerifyPassword(tc.password+"x", tc.hash) {
				t.Fatal("a wrong password was accepted")
			}
		})
	}
}

func TestSHACryptHashesNeedRehash(t *testing.T) {
	const cryptHash = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu" +
		"esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
	if !NeedsRehash(cryptHash) {
		t.Fatal("a crypt(3) hash should be flagged for upgrade to argon2id")
	}
}

func TestVerifySHACryptRejectsMalformed(t *testing.T) {
	for _, encoded := range []string{
		"$6$",
		"$6$onlysalt",
		"$6$salt$",
		"$7$salt$hash",
		"$6$rounds=abc$salt$hash",
		"$6$rounds=10000$salt",
	} {
		if VerifyPassword("anything", encoded) {
			t.Errorf("accepted malformed crypt hash %q", encoded)
		}
	}
}

func TestSHACryptSaltIsTruncatedAtSixteen(t *testing.T) {
	// crypt(3) ignores salt beyond 16 characters. A hash string carrying a
	// longer salt must therefore verify against the digest computed from just
	// the first 16, or hashes written by such a system would be unusable.
	digest := shaCrypt("6", "pw", "0123456789abcdef", shaCryptDefaultRounds)
	if !VerifyPassword("pw", "$6$0123456789abcdefEXTRA$"+digest) {
		t.Fatal("salt was not truncated to 16 characters before hashing")
	}
}

func TestSHACryptRoundsAreClamped(t *testing.T) {
	// Values outside the permitted range are clamped rather than rejected,
	// matching crypt(3), so a hash written with an out-of-range count still
	// verifies.
	if got := clampRounds(10); got != shaCryptMinRounds {
		t.Errorf("clampRounds(10) = %d, want %d", got, shaCryptMinRounds)
	}
	if got := clampRounds(1 << 40); got != shaCryptMaxRounds {
		t.Errorf("clampRounds(huge) = %d, want %d", got, shaCryptMaxRounds)
	}
	if got := clampRounds(5000); got != 5000 {
		t.Errorf("clampRounds(5000) = %d", got)
	}
}
