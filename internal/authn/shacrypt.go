package authn

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"strconv"
	"strings"
)

// SHA-crypt verification, per Ulrich Drepper's specification.
//
// This exists so that identities migrated out of the file-based configuration
// keep working: those password hashes were produced by crypt(3) (what
// `openssl passwd -6` emits), a format the Go standard library does not
// implement. Existing hashes are accepted on login and then upgraded to
// argon2id, so the format drains away rather than being carried forward. New
// hashes are never created in this format.

const (
	shaCryptDefaultRounds = 5000
	shaCryptMinRounds     = 1000
	shaCryptMaxRounds     = 999999999
	shaCryptMaxSaltLen    = 16
)

// itoa64 is the alphabet crypt(3) uses, which is not standard base64 and is not
// in the same order.
const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// isSHACryptHash reports whether encoded looks like a $5$ or $6$ crypt hash.
func isSHACryptHash(encoded string) bool {
	return strings.HasPrefix(encoded, "$5$") || strings.HasPrefix(encoded, "$6$")
}

// verifySHACrypt recomputes the hash from the password and the parameters
// embedded in encoded, and compares in constant time.
func verifySHACrypt(password, encoded string) bool {
	prefix, rounds, salt, wantHash, ok := parseSHACrypt(encoded)
	if !ok {
		return false
	}
	got := shaCrypt(prefix, password, salt, rounds)
	return subtle.ConstantTimeCompare([]byte(got), []byte(wantHash)) == 1
}

// parseSHACrypt splits "$<id>$[rounds=N$]<salt>$<hash>".
func parseSHACrypt(encoded string) (prefix string, rounds int, salt, hash string, ok bool) {
	parts := strings.Split(encoded, "$")
	// A well-formed hash is ["", id, (rounds=N,)? salt, hash].
	if len(parts) < 4 || parts[0] != "" {
		return "", 0, "", "", false
	}
	prefix = parts[1]
	if prefix != "5" && prefix != "6" {
		return "", 0, "", "", false
	}
	rounds = shaCryptDefaultRounds
	rest := parts[2:]
	if strings.HasPrefix(rest[0], "rounds=") {
		if len(rest) < 3 {
			return "", 0, "", "", false
		}
		n, err := strconv.Atoi(strings.TrimPrefix(rest[0], "rounds="))
		if err != nil {
			return "", 0, "", "", false
		}
		rounds = clampRounds(n)
		rest = rest[1:]
	}
	if len(rest) != 2 {
		return "", 0, "", "", false
	}
	salt, hash = rest[0], rest[1]
	if len(salt) > shaCryptMaxSaltLen {
		salt = salt[:shaCryptMaxSaltLen]
	}
	if hash == "" {
		return "", 0, "", "", false
	}
	return prefix, rounds, salt, hash, true
}

func clampRounds(n int) int {
	if n < shaCryptMinRounds {
		return shaCryptMinRounds
	}
	if n > shaCryptMaxRounds {
		return shaCryptMaxRounds
	}
	return n
}

// shaCrypt computes the encoded hash portion (without the $id$salt$ prefix).
func shaCrypt(prefix, password, salt string, rounds int) string {
	var (
		newHash func() hash.Hash
		size    int
	)
	if prefix == "6" {
		newHash, size = sha512.New, sha512.Size
	} else {
		newHash, size = sha256.New, sha256.Size
	}

	key := []byte(password)
	saltBytes := []byte(salt)

	// Digest B is the password and salt folded together; it seeds everything
	// that follows.
	b := newHash()
	b.Write(key)
	b.Write(saltBytes)
	b.Write(key)
	digestB := b.Sum(nil)

	// Digest A mixes in |password| bytes of B, then walks the bit pattern of
	// the password length choosing between B and the password itself.
	a := newHash()
	a.Write(key)
	a.Write(saltBytes)
	writeRepeated(a, digestB, len(key))
	for i := len(key); i > 0; i >>= 1 {
		if i&1 != 0 {
			a.Write(digestB)
		} else {
			a.Write(key)
		}
	}
	digestA := a.Sum(nil)

	// Sequence P is |password| bytes derived from the password alone.
	dp := newHash()
	for i := 0; i < len(key); i++ {
		dp.Write(key)
	}
	sequenceP := repeatToLength(dp.Sum(nil), len(key))

	// Sequence S is |salt| bytes derived from the salt, with the repeat count
	// perturbed by the first byte of A.
	ds := newHash()
	for i := 0; i < 16+int(digestA[0]); i++ {
		ds.Write(saltBytes)
	}
	sequenceS := repeatToLength(ds.Sum(nil), len(saltBytes))

	// The stretching loop: the cost comes from repeating this `rounds` times.
	c := make([]byte, size)
	copy(c, digestA)
	for i := 0; i < rounds; i++ {
		h := newHash()
		if i&1 != 0 {
			h.Write(sequenceP)
		} else {
			h.Write(c)
		}
		if i%3 != 0 {
			h.Write(sequenceS)
		}
		if i%7 != 0 {
			h.Write(sequenceP)
		}
		if i&1 != 0 {
			h.Write(c)
		} else {
			h.Write(sequenceP)
		}
		c = h.Sum(nil)
	}

	if prefix == "6" {
		return encodeSHA512Crypt(c)
	}
	return encodeSHA256Crypt(c)
}

// writeRepeated writes n bytes taken from block, repeating it as needed.
func writeRepeated(h hash.Hash, block []byte, n int) {
	for n > len(block) {
		h.Write(block)
		n -= len(block)
	}
	h.Write(block[:n])
}

// repeatToLength returns n bytes taken from block, repeating it as needed.
func repeatToLength(block []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		remaining := n - len(out)
		if remaining >= len(block) {
			out = append(out, block...)
			continue
		}
		out = append(out, block[:remaining]...)
	}
	return out
}

// b64From24Bit emits n characters of the crypt alphabet from three bytes, least
// significant group first.
func b64From24Bit(b2, b1, b0 byte, n int, out *strings.Builder) {
	w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	for i := 0; i < n; i++ {
		out.WriteByte(itoa64[w&0x3f])
		w >>= 6
	}
}

// encodeSHA512Crypt applies the byte permutation crypt(3) uses for $6$.
func encodeSHA512Crypt(c []byte) string {
	var out strings.Builder
	out.Grow(86)
	groups := [][3]int{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26},
		{6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32},
		{12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38},
		{18, 39, 60}, {40, 61, 19}, {62, 20, 41},
	}
	for _, g := range groups {
		b64From24Bit(c[g[0]], c[g[1]], c[g[2]], 4, &out)
	}
	b64From24Bit(0, 0, c[63], 2, &out)
	return out.String()
}

// encodeSHA256Crypt applies the byte permutation crypt(3) uses for $5$.
func encodeSHA256Crypt(c []byte) string {
	var out strings.Builder
	out.Grow(43)
	groups := [][3]int{
		{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14},
		{15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29},
	}
	for _, g := range groups {
		b64From24Bit(c[g[0]], c[g[1]], c[g[2]], 4, &out)
	}
	b64From24Bit(0, c[31], c[30], 3, &out)
	return out.String()
}
