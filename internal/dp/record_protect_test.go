package dp

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeRecording(t *testing.T, opts RecorderOptions, lines []string) string {
	t.Helper()
	if opts.Path == "" {
		opts.Path = filepath.Join(t.TempDir(), "session"+recordingExtension(opts.Compress, len(opts.EncryptionKey) > 0))
	}
	if opts.StartedAt.IsZero() {
		opts.StartedAt = time.Now()
	}
	recorder, err := NewRecorder(opts)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	for _, line := range lines {
		recorder.Output([]byte(line))
	}
	if err := recorder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return opts.Path
}

func readRecording(t *testing.T, path string, key []byte) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open recording: %v", err)
	}
	defer func() { _ = file.Close() }()

	reader, err := OpenRecording(file, key)
	if err != nil {
		t.Fatalf("OpenRecording: %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	return string(data)
}

func TestPlainRecordingRoundTrip(t *testing.T) {
	path := writeRecording(t, RecorderOptions{}, []string{"hello\n", "world\n"})
	content := readRecording(t, path, nil)

	if !strings.Contains(content, `"version":2`) {
		t.Errorf("header missing: %s", content)
	}
	if !strings.Contains(content, "hello") || !strings.Contains(content, "world") {
		t.Errorf("content missing: %s", content)
	}
}

func TestCompressedRecordingRoundTrip(t *testing.T) {
	// Terminal output is overwhelmingly repetitive, which is what makes keeping
	// a compliance period's worth of recordings affordable.
	repetitive := strings.Repeat("the same line of output\n", 500)
	path := writeRecording(t, RecorderOptions{Compress: true}, []string{repetitive})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() >= int64(len(repetitive))/4 {
		t.Errorf("compressed recording is %d bytes for %d bytes of output; compression is not working",
			info.Size(), len(repetitive))
	}
	if !strings.HasSuffix(path, ".gz") {
		t.Errorf("the file name should say what it is: %s", path)
	}

	content := readRecording(t, path, nil)
	if !strings.Contains(content, "the same line of output") {
		t.Error("the compressed recording did not read back")
	}
}

func TestEncryptedRecordingRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	const secret = "user typed a password: hunter2"
	path := writeRecording(t, RecorderOptions{EncryptionKey: key}, []string{secret + "\n"})

	// The point is that reading the disk is not the same as reading sessions.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("the recording contains the plaintext on disk")
	}
	if bytes.Contains(raw, []byte(`"version":2`)) {
		t.Fatal("even the header is readable, so the container is not encrypted")
	}

	content := readRecording(t, path, key)
	if !strings.Contains(content, secret) {
		t.Fatalf("the recording did not decrypt: %s", content)
	}
}

func TestCompressedAndEncryptedRecording(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(255 - i)
	}
	// Compression must happen before encryption; the other order leaves the
	// compressor nothing to find, since ciphertext is incompressible.
	repetitive := strings.Repeat("output line\n", 500)
	path := writeRecording(t, RecorderOptions{Compress: true, EncryptionKey: key}, []string{repetitive})

	info, _ := os.Stat(path)
	if info.Size() >= int64(len(repetitive))/4 {
		t.Errorf("size %d suggests the data was encrypted before it was compressed", info.Size())
	}
	if !strings.HasSuffix(path, ".cast.gz.enc") {
		t.Errorf("name = %s", path)
	}

	content := readRecording(t, path, key)
	if !strings.Contains(content, "output line") {
		t.Error("the recording did not read back")
	}
}

func TestEncryptedRecordingRejectsTheWrongKey(t *testing.T) {
	key := make([]byte, 32)
	other := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
		other[i] = byte(i + 1)
	}
	path := writeRecording(t, RecorderOptions{EncryptionKey: key}, []string{"secret output\n"})

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = file.Close() }()

	reader, err := OpenRecording(file, other)
	if err != nil {
		return // refusing up front is fine
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("a recording decrypted under the wrong key")
	}
}

func TestEncryptedRecordingDetectsTampering(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	path := writeRecording(t, RecorderOptions{EncryptionKey: key},
		[]string{"the operator ran a dangerous command\n"})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Flip a byte well past the header, inside the sealed chunk.
	raw[len(raw)-5] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	file, _ := os.Open(path)
	defer func() { _ = file.Close() }()
	reader, err := OpenRecording(file, key)
	if err != nil {
		return
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("an altered recording read back as if it were intact")
	}
}

func TestEncryptedRecordingWithoutAKeyIsRefused(t *testing.T) {
	key := make([]byte, 32)
	path := writeRecording(t, RecorderOptions{EncryptionKey: key}, []string{"output\n"})

	file, _ := os.Open(path)
	defer func() { _ = file.Close() }()
	if _, err := OpenRecording(file, nil); err == nil {
		t.Fatal("an encrypted recording opened without a key")
	} else if !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("the error should say the recording is encrypted, got %v", err)
	}
}

func TestLargeRecordingSpansMultipleChunks(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	// More than one chunk, so the nonce counter and chunk framing are actually
	// exercised rather than assumed.
	var lines []string
	for i := 0; i < 4000; i++ {
		lines = append(lines, "line of terminal output number to make this long enough\n")
	}
	path := writeRecording(t, RecorderOptions{EncryptionKey: key}, lines)

	content := readRecording(t, path, key)
	if got := strings.Count(content, "line of terminal output"); got != len(lines) {
		t.Fatalf("read back %d lines, wrote %d; chunk framing is wrong", got, len(lines))
	}
}

func TestRecordingKeyValidation(t *testing.T) {
	if _, err := recordingKeyBytes(""); err != nil {
		t.Errorf("an empty key should be accepted as no encryption: %v", err)
	}
	if _, err := recordingKeyBytes("not hex"); err == nil {
		t.Error("a non-hex key should be rejected")
	}
	if _, err := recordingKeyBytes(hex.EncodeToString([]byte("short"))); err == nil {
		t.Error("a short key should be rejected")
	}

	generated, err := GenerateRecordingKey()
	if err != nil {
		t.Fatalf("GenerateRecordingKey: %v", err)
	}
	key, err := recordingKeyBytes(generated)
	if err != nil || len(key) != 32 {
		t.Fatalf("a generated key should validate: %d bytes, %v", len(key), err)
	}
}

func TestRecordingExtensionDescribesTheContainer(t *testing.T) {
	cases := []struct {
		compress, encrypt bool
		want              string
	}{
		{false, false, ".cast"},
		{true, false, ".cast.gz"},
		{false, true, ".cast.enc"},
		{true, true, ".cast.gz.enc"},
	}
	for _, tc := range cases {
		if got := recordingExtension(tc.compress, tc.encrypt); got != tc.want {
			t.Errorf("recordingExtension(%v, %v) = %q, want %q", tc.compress, tc.encrypt, got, tc.want)
		}
	}
}
