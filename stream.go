package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	streamMagic     = "SECS2"
	streamChunkSize = 64 << 10
	streamFinal     = byte(1)
)

// NewEncryptWriter returns an authenticated streaming writer. Close must be
// called to write the authenticated final record.
func (c *Cipher) NewEncryptWriter(w io.Writer) (io.WriteCloser, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if w == nil {
		return nil, errors.New("secure: nil writer")
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(c.cfg.rand, salt); err != nil {
		return nil, err
	}
	header := append([]byte(streamMagic), modeKey)
	header = append(header, salt...)
	key, err := deriveStreamKey(c.key[:], salt)
	if err != nil {
		return nil, err
	}
	return newEncryptWriter(w, key, header)
}

// NewDecryptReader reads and authenticates a key-based stream.
func (c *Cipher) NewDecryptReader(r io.Reader) (io.Reader, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	header, salt, _, err := readStreamHeader(r, modeKey)
	if err != nil {
		return nil, err
	}
	key, err := deriveStreamKey(c.key[:], salt)
	if err != nil {
		return nil, err
	}
	return newDecryptReader(r, key, header)
}

func (p *PasswordCipher) NewEncryptWriter(w io.Writer) (io.WriteCloser, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if w == nil {
		return nil, errors.New("secure: nil writer")
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(p.cfg.rand, salt); err != nil {
		return nil, err
	}
	header := append([]byte(streamMagic), modePassword)
	params := make([]byte, 9)
	binary.BigEndian.PutUint32(params[:4], p.cfg.argon.Time)
	binary.BigEndian.PutUint32(params[4:8], p.cfg.argon.Memory)
	params[8] = p.cfg.argon.Threads
	header = append(header, params...)
	header = append(header, salt...)
	key := argon2.IDKey(p.passphrase, salt, p.cfg.argon.Time, p.cfg.argon.Memory, p.cfg.argon.Threads, keySize)
	return newEncryptWriter(w, key, header)
}

func (p *PasswordCipher) NewDecryptReader(r io.Reader) (io.Reader, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	header, salt, params, err := readStreamHeader(r, modePassword)
	if err != nil {
		return nil, err
	}
	if err := validateArgon2(params); err != nil {
		return nil, err
	}
	key := argon2.IDKey(p.passphrase, salt, params.Time, params.Memory, params.Threads, keySize)
	return newDecryptReader(r, key, header)
}

func deriveStreamKey(master, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, master, salt, []byte("github.com/rusq/secure/v2 stream key"))
	key := make([]byte, keySize)
	_, err := io.ReadFull(r, key)
	return key, err
}

func readStreamHeader(r io.Reader, wantMode byte) ([]byte, []byte, Argon2Parameters, error) {
	if r == nil {
		return nil, nil, Argon2Parameters{}, errors.New("secure: nil reader")
	}
	base := make([]byte, len(streamMagic)+1)
	if _, err := io.ReadFull(r, base); err != nil {
		return nil, nil, Argon2Parameters{}, ErrTruncated
	}
	if string(base[:len(streamMagic)]) != streamMagic || base[len(streamMagic)] != wantMode {
		return nil, nil, Argon2Parameters{}, ErrInvalidEnvelope
	}
	header := append([]byte(nil), base...)
	var params Argon2Parameters
	if wantMode == modePassword {
		encoded := make([]byte, 9)
		if _, err := io.ReadFull(r, encoded); err != nil {
			return nil, nil, params, ErrTruncated
		}
		header = append(header, encoded...)
		params = Argon2Parameters{binary.BigEndian.Uint32(encoded[:4]), binary.BigEndian.Uint32(encoded[4:8]), encoded[8]}
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, nil, params, ErrTruncated
	}
	header = append(header, salt...)
	return header, salt, params, nil
}

func streamAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type encryptWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	header  []byte
	buffer  []byte
	counter uint64
	closed  bool
	err     error
}

func newEncryptWriter(w io.Writer, key, header []byte) (*encryptWriter, error) {
	aead, err := streamAEAD(key)
	if err != nil {
		return nil, err
	}
	if err := writeAll(w, header); err != nil {
		return nil, err
	}
	return &encryptWriter{w: w, aead: aead, header: header, buffer: make([]byte, 0, streamChunkSize)}, nil
}

func (w *encryptWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("secure: write after close")
	}
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), streamChunkSize-len(w.buffer))
		w.buffer = append(w.buffer, p[:n]...)
		p = p[n:]
		written += n
		if len(w.buffer) == streamChunkSize {
			if err := w.writeRecord(w.buffer, 0); err != nil {
				w.err = err
				return written, err
			}
			w.buffer = w.buffer[:0]
		}
	}
	return written, nil
}

func (w *encryptWriter) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if len(w.buffer) > 0 {
		if err := w.writeRecord(w.buffer, 0); err != nil {
			w.err = err
			return err
		}
	}
	w.err = w.writeRecord(nil, streamFinal)
	return w.err
}

func (w *encryptWriter) writeRecord(plaintext []byte, flags byte) error {
	if w.counter == ^uint64(0) {
		return ErrLimitExceeded
	}
	recordHeader := make([]byte, 5)
	binary.BigEndian.PutUint32(recordHeader[:4], uint32(len(plaintext)))
	recordHeader[4] = flags
	nonce := streamNonce(w.counter)
	ciphertext := w.aead.Seal(nil, nonce, plaintext, streamAAD(w.header, w.counter, recordHeader))
	if err := writeAll(w.w, recordHeader); err != nil {
		return err
	}
	if err := writeAll(w.w, ciphertext); err != nil {
		return err
	}
	w.counter++
	return nil
}

type decryptReader struct {
	r       io.Reader
	aead    cipher.AEAD
	header  []byte
	buffer  []byte
	counter uint64
	done    bool
	err     error
}

func newDecryptReader(r io.Reader, key, header []byte) (*decryptReader, error) {
	aead, err := streamAEAD(key)
	if err != nil {
		return nil, err
	}
	return &decryptReader{r: r, aead: aead, header: header}, nil
}

func (r *decryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.buffer) == 0 && !r.done && r.err == nil {
		r.readRecord()
	}
	if len(r.buffer) > 0 {
		n := copy(p, r.buffer)
		r.buffer = r.buffer[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	return 0, io.EOF
}

func (r *decryptReader) readRecord() {
	recordHeader := make([]byte, 5)
	if _, err := io.ReadFull(r.r, recordHeader); err != nil {
		r.err = ErrTruncated
		return
	}
	length := binary.BigEndian.Uint32(recordHeader[:4])
	flags := recordHeader[4]
	if length > streamChunkSize || flags&^streamFinal != 0 || flags == streamFinal && length != 0 {
		r.err = ErrInvalidEnvelope
		return
	}
	ciphertext := make([]byte, int(length)+r.aead.Overhead())
	if _, err := io.ReadFull(r.r, ciphertext); err != nil {
		r.err = ErrTruncated
		return
	}
	plaintext, err := r.aead.Open(nil, streamNonce(r.counter), ciphertext, streamAAD(r.header, r.counter, recordHeader))
	if err != nil {
		r.err = ErrAuthentication
		return
	}
	r.counter++
	if flags == streamFinal {
		r.done = true
		return
	}
	r.buffer = plaintext
}

func streamNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func streamAAD(header []byte, counter uint64, recordHeader []byte) []byte {
	aad := make([]byte, 0, len(header)+8+len(recordHeader))
	aad = append(aad, header...)
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], counter)
	aad = append(aad, count[:]...)
	aad = append(aad, recordHeader...)
	return aad
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
