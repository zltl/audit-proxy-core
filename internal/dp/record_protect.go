package dp

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Session recordings are a verbatim transcript of a privileged session. They
// contain whatever the user typed, which routinely includes passwords entered
// at an upstream prompt, tokens pasted into a shell, and the contents of files
// they opened. Storing them as plain text that lives forever turns the audit
// trail into the most valuable thing on the disk.
//
// Two things address that. Compression, because these files are overwhelmingly
// repetitive terminal output and shrink by an order of magnitude, which makes
// retaining them for a compliance period affordable. And encryption, so that
// reading the disk is not the same as reading the sessions.

// recordingExtension returns the file suffix for the configured protection, so
// that what a file is is evident from its name rather than from trying to parse
// it.
func recordingExtension(compress, encrypt bool) string {
	name := ".cast"
	if compress {
		name += ".gz"
	}
	if encrypt {
		name += ".enc"
	}
	return name
}

// recordingWriterChain builds the writer a recording is written through.
//
// The order matters: compress first, then encrypt. Encrypting first would leave
// nothing for the compressor to find, since ciphertext is incompressible by
// construction.
func recordingWriterChain(sink io.WriteCloser, compress bool, key []byte) (io.WriteCloser, error) {
	var writer io.WriteCloser = sink
	if len(key) > 0 {
		encrypted, err := newEncryptingWriter(writer, key)
		if err != nil {
			return nil, err
		}
		writer = encrypted
	}
	if compress {
		writer = &gzipWriteCloser{gz: gzip.NewWriter(writer), under: writer}
	}
	return writer, nil
}

// gzipWriteCloser closes the compressor and then what it wrote to, which a bare
// gzip.Writer does not do and which would otherwise truncate every recording.
type gzipWriteCloser struct {
	gz    *gzip.Writer
	under io.WriteCloser
}

func (w *gzipWriteCloser) Write(p []byte) (int, error) { return w.gz.Write(p) }

func (w *gzipWriteCloser) Close() error {
	err := w.gz.Close()
	if closeErr := w.under.Close(); err == nil {
		err = closeErr
	}
	return err
}

// Flush pushes buffered data through the compressor, which is what makes a
// recording readable while the session is still running.
func (w *gzipWriteCloser) Flush() error { return w.gz.Flush() }

// recordingChunkSize bounds how much plaintext goes into one sealed chunk.
//
// A recording is written progressively, so it cannot be one AEAD message: the
// file has to be readable before the session ends, and holding the whole
// session in memory to seal at the end would be worse. Chunking keeps each
// piece independently verifiable at the cost of a nonce and tag per chunk.
const recordingChunkSize = 64 * 1024

// recordingMagic identifies the container so a reader can tell an encrypted
// recording from a plain one without guessing.
var recordingMagic = [8]byte{'S', 'S', 'H', 'P', 'R', 'E', 'C', 1}

// encryptingWriter seals a stream in chunks.
type encryptingWriter struct {
	sink io.WriteCloser
	aead cipher.AEAD
	buf  []byte
	// counter is folded into each nonce so that two chunks of one recording
	// never share one, which would be fatal for GCM.
	counter uint64
	closed  bool
}

func newEncryptingWriter(sink io.WriteCloser, key []byte) (*encryptingWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("dp: recording cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("dp: recording aead: %w", err)
	}
	if _, err := sink.Write(recordingMagic[:]); err != nil {
		return nil, fmt.Errorf("dp: write recording header: %w", err)
	}
	return &encryptingWriter{sink: sink, aead: aead, buf: make([]byte, 0, recordingChunkSize)}, nil
}

func (w *encryptingWriter) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		space := recordingChunkSize - len(w.buf)
		if space > len(p) {
			space = len(p)
		}
		w.buf = append(w.buf, p[:space]...)
		p = p[space:]
		if len(w.buf) == recordingChunkSize {
			if err := w.sealChunk(); err != nil {
				return 0, err
			}
		}
	}
	return written, nil
}

// Flush seals whatever is buffered, so a reader can follow a live recording
// rather than waiting for the session to end.
func (w *encryptingWriter) Flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	return w.sealChunk()
}

func (w *encryptingWriter) sealChunk() error {
	nonce := make([]byte, w.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], w.counter)
	w.counter++

	sealed := w.aead.Seal(nil, nonce, w.buf, nil)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(sealed)))
	if _, err := w.sink.Write(header[:]); err != nil {
		return fmt.Errorf("dp: write chunk header: %w", err)
	}
	if _, err := w.sink.Write(sealed); err != nil {
		return fmt.Errorf("dp: write chunk: %w", err)
	}
	w.buf = w.buf[:0]
	return nil
}

func (w *encryptingWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	err := w.Flush()
	if closeErr := w.sink.Close(); err == nil {
		err = closeErr
	}
	return err
}

// OpenRecording reads a recording back, undoing whatever protection was applied.
//
// A recording nobody can replay is not an audit trail, so the reader is part of
// the feature rather than something to write later.
func OpenRecording(source io.Reader, key []byte) (io.Reader, error) {
	buffered := &peekReader{source: source}
	magic, err := buffered.peek(len(recordingMagic))
	if err != nil && err != io.EOF {
		return nil, err
	}

	var reader io.Reader = buffered
	if len(magic) == len(recordingMagic) && string(magic) == string(recordingMagic[:]) {
		if len(key) == 0 {
			return nil, fmt.Errorf("dp: the recording is encrypted but no key was supplied")
		}
		if _, err := buffered.discard(len(recordingMagic)); err != nil {
			return nil, err
		}
		decrypted, err := newDecryptingReader(buffered, key)
		if err != nil {
			return nil, err
		}
		reader = decrypted
	}

	// Compression is detected from the gzip magic rather than the file name, so
	// a renamed file still reads.
	peeked := &peekReader{source: reader}
	header, err := peeked.peek(2)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(header) == 2 && header[0] == 0x1f && header[1] == 0x8b {
		return gzip.NewReader(peeked)
	}
	return peeked, nil
}

// decryptingReader reverses encryptingWriter.
type decryptingReader struct {
	source  io.Reader
	aead    cipher.AEAD
	counter uint64
	pending []byte
}

func newDecryptingReader(source io.Reader, key []byte) (*decryptingReader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("dp: recording cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("dp: recording aead: %w", err)
	}
	return &decryptingReader{source: source, aead: aead}, nil
}

func (r *decryptingReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		var header [4]byte
		if _, err := io.ReadFull(r.source, header[:]); err != nil {
			if err == io.ErrUnexpectedEOF {
				// A truncated tail is what a crashed proxy leaves behind. The
				// chunks before it are still valid and worth returning.
				return 0, io.EOF
			}
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 || length > recordingChunkSize+uint32(r.aead.Overhead())+16 {
			return 0, fmt.Errorf("dp: recording chunk length %d is out of range", length)
		}
		sealed := make([]byte, length)
		if _, err := io.ReadFull(r.source, sealed); err != nil {
			return 0, io.EOF
		}
		nonce := make([]byte, r.aead.NonceSize())
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], r.counter)
		r.counter++

		plaintext, err := r.aead.Open(nil, nonce, sealed, nil)
		if err != nil {
			return 0, fmt.Errorf("dp: the recording has been altered or the key is wrong")
		}
		r.pending = plaintext
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// peekReader allows looking at the first bytes of a stream without consuming
// them, which is how the container format is detected.
type peekReader struct {
	source io.Reader
	buf    []byte
}

func (r *peekReader) peek(n int) ([]byte, error) {
	for len(r.buf) < n {
		chunk := make([]byte, n-len(r.buf))
		read, err := r.source.Read(chunk)
		r.buf = append(r.buf, chunk[:read]...)
		if err != nil {
			return r.buf, err
		}
		if read == 0 {
			break
		}
	}
	return r.buf, nil
}

func (r *peekReader) discard(n int) (int, error) {
	if n > len(r.buf) {
		n = len(r.buf)
	}
	r.buf = r.buf[n:]
	return n, nil
}

func (r *peekReader) Read(p []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	return r.source.Read(p)
}

// recordingKeyBytes decodes the configured recording key.
func recordingKeyBytes(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("dp: recording_encryption_key must be hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("dp: recording_encryption_key must be 32 bytes (64 hex characters), got %d", len(key))
	}
	return key, nil
}

// GenerateRecordingKey returns a fresh key, for tooling that provisions one.
func GenerateRecordingKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
