// Package secure provides versioned, authenticated encryption for byte
// slices, strings, JSON values, and streams.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	prefix             = "SEC2."
	envelopeVersion    = 2
	modeKey            = 1
	modePassword       = 2
	keySize            = 32
	saltSize           = 16
	defaultMaxEnvelope = 16 << 20

	defaultArgonTime    = uint32(3)
	defaultArgonMemory  = uint32(64 * 1024)
	defaultArgonThreads = uint8(4)
	maxArgonTime        = uint32(10)
	maxArgonMemory      = uint32(256 * 1024)
	maxArgonThreads     = uint8(16)
)

// Codec is implemented by encryption contexts usable by the JSON helpers.
type Codec interface {
	Seal(plaintext, additionalData []byte) (string, error)
	Open(envelope string, additionalData []byte) ([]byte, error)
}

type config struct {
	maxEnvelope int
	rand        io.Reader
}

// Option configures a Cipher.
type Option func(*config) error

// WithMaxEnvelopeSize limits the decoded envelope size accepted or produced.
func WithMaxEnvelopeSize(n int) Option {
	return func(c *config) error {
		if n < 64 {
			return fmt.Errorf("%w: envelope size must be at least 64 bytes", ErrLimitExceeded)
		}
		c.maxEnvelope = n
		return nil
	}
}

func newConfig(opts []Option) (config, error) {
	c := config{maxEnvelope: defaultMaxEnvelope, rand: rand.Reader}
	for _, opt := range opts {
		if opt == nil {
			return config{}, fmt.Errorf("%w: nil option", ErrInvalidEnvelope)
		}
		if err := opt(&c); err != nil {
			return config{}, err
		}
	}
	return c, nil
}

// Cipher is an immutable AES-256-GCM encryption context.
type Cipher struct {
	key [keySize]byte
	cfg config
}

func (c *Cipher) validate() error {
	if c == nil || c.cfg.maxEnvelope == 0 || c.cfg.rand == nil {
		return ErrUnconfigured
	}
	return nil
}

// NewCipher creates a key-based encryption context. key must contain 32 bytes.
func NewCipher(key []byte, opts ...Option) (*Cipher, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("secure: key must be %d bytes", keySize)
	}
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}
	c := &Cipher{cfg: cfg}
	copy(c.key[:], key)
	return c, nil
}

// Argon2Parameters controls password key derivation. Memory is measured in KiB.
type Argon2Parameters struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

func defaultArgon2Parameters() Argon2Parameters {
	return Argon2Parameters{defaultArgonTime, defaultArgonMemory, defaultArgonThreads}
}

func validateArgon2(p Argon2Parameters) error {
	if p.Time < defaultArgonTime || p.Memory < defaultArgonMemory || p.Threads < defaultArgonThreads {
		return fmt.Errorf("%w: Argon2id parameters are below the security minimum", ErrLimitExceeded)
	}
	if p.Time > maxArgonTime || p.Memory > maxArgonMemory || p.Threads > maxArgonThreads {
		return fmt.Errorf("%w: Argon2id parameters exceed resource limits", ErrLimitExceeded)
	}
	return nil
}

type passwordConfig struct {
	config
	argon Argon2Parameters
}

// PasswordOption configures a PasswordCipher.
type PasswordOption func(*passwordConfig) error

// WithPasswordMaxEnvelopeSize sets the decoded envelope limit.
func WithPasswordMaxEnvelopeSize(n int) PasswordOption {
	return func(c *passwordConfig) error {
		return WithMaxEnvelopeSize(n)(&c.config)
	}
}

// WithArgon2Parameters raises the Argon2id work factors used for new data.
func WithArgon2Parameters(p Argon2Parameters) PasswordOption {
	return func(c *passwordConfig) error {
		if err := validateArgon2(p); err != nil {
			return err
		}
		c.argon = p
		return nil
	}
}

// PasswordCipher encrypts with a password and a fresh Argon2id salt per item.
type PasswordCipher struct {
	passphrase []byte
	cfg        passwordConfig
}

func (p *PasswordCipher) validate() error {
	if p == nil || len(p.passphrase) == 0 || p.cfg.maxEnvelope == 0 || p.cfg.rand == nil {
		return ErrUnconfigured
	}
	return nil
}

// NewPasswordCipher creates a password-based encryption context.
func NewPasswordCipher(passphrase []byte, opts ...PasswordOption) (*PasswordCipher, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("secure: empty passphrase")
	}
	cfg := passwordConfig{config: config{maxEnvelope: defaultMaxEnvelope, rand: rand.Reader}, argon: defaultArgon2Parameters()}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option", ErrInvalidEnvelope)
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	return &PasswordCipher{passphrase: append([]byte(nil), passphrase...), cfg: cfg}, nil
}

// Seal encrypts plaintext and authenticates additionalData without storing it.
func (c *Cipher) Seal(plaintext, additionalData []byte) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	return sealWithKey(c.key[:], modeKey, nil, plaintext, additionalData, c.cfg)
}

// Open authenticates and decrypts a key-based SEC2 envelope.
func (c *Cipher) Open(envelope string, additionalData []byte) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if len(additionalData) > c.cfg.maxEnvelope {
		return nil, ErrLimitExceeded
	}
	header, nonce, ciphertext, err := parseEnvelope(envelope, c.cfg.maxEnvelope)
	if err != nil {
		return nil, err
	}
	if header[1] != modeKey {
		return nil, fmt.Errorf("%w: envelope requires a password", ErrInvalidEnvelope)
	}
	return openAEAD(c.key[:], header, nonce, ciphertext, additionalData)
}

// EncryptString encrypts a UTF-8 string without additional data.
func (c *Cipher) EncryptString(plaintext string) (string, error) {
	return c.Seal([]byte(plaintext), nil)
}

// DecryptString decrypts a UTF-8 string without additional data.
func (c *Cipher) DecryptString(envelope string) (string, error) {
	b, err := c.Open(envelope, nil)
	return string(b), err
}

// Seal encrypts plaintext using a fresh salt and Argon2id-derived key.
func (p *PasswordCipher) Seal(plaintext, additionalData []byte) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	if err := checkSealSize(2+4+4+1+saltSize, len(plaintext), len(additionalData), p.cfg.maxEnvelope); err != nil {
		return "", err
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(p.cfg.rand, salt); err != nil {
		return "", fmt.Errorf("secure: generate salt: %w", err)
	}
	header := passwordHeader(p.cfg.argon, salt)
	key := argon2.IDKey(p.passphrase, salt, p.cfg.argon.Time, p.cfg.argon.Memory, p.cfg.argon.Threads, keySize)
	return sealWithKey(key, modePassword, header[2:], plaintext, additionalData, p.cfg.config)
}

// Open authenticates and decrypts a password-based SEC2 envelope.
func (p *PasswordCipher) Open(envelope string, additionalData []byte) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if len(additionalData) > p.cfg.maxEnvelope {
		return nil, ErrLimitExceeded
	}
	header, nonce, ciphertext, err := parseEnvelope(envelope, p.cfg.maxEnvelope)
	if err != nil {
		return nil, err
	}
	if header[1] != modePassword || len(header) != 2+4+4+1+saltSize {
		return nil, fmt.Errorf("%w: envelope does not contain password parameters", ErrInvalidEnvelope)
	}
	params := Argon2Parameters{binary.BigEndian.Uint32(header[2:6]), binary.BigEndian.Uint32(header[6:10]), header[10]}
	if err := validateArgon2(params); err != nil {
		return nil, err
	}
	salt := header[11 : 11+saltSize]
	key := argon2.IDKey(p.passphrase, salt, params.Time, params.Memory, params.Threads, keySize)
	return openAEAD(key, header, nonce, ciphertext, additionalData)
}

func (p *PasswordCipher) EncryptString(plaintext string) (string, error) {
	return p.Seal([]byte(plaintext), nil)
}

func (p *PasswordCipher) DecryptString(envelope string) (string, error) {
	b, err := p.Open(envelope, nil)
	return string(b), err
}

func passwordHeader(p Argon2Parameters, salt []byte) []byte {
	h := make([]byte, 2+4+4+1+saltSize)
	h[0], h[1] = envelopeVersion, modePassword
	binary.BigEndian.PutUint32(h[2:6], p.Time)
	binary.BigEndian.PutUint32(h[6:10], p.Memory)
	h[10] = p.Threads
	copy(h[11:], salt)
	return h
}

func sealWithKey(key []byte, mode byte, extraHeader, plaintext, additionalData []byte, cfg config) (string, error) {
	header := append([]byte{envelopeVersion, mode}, extraHeader...)
	if err := checkSealSize(len(header), len(plaintext), len(additionalData), cfg.maxEnvelope); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(cfg.rand, nonce); err != nil {
		return "", fmt.Errorf("secure: generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, envelopeAAD(header, additionalData))
	packedLen := len(header) + len(nonce) + len(ciphertext)
	if packedLen > cfg.maxEnvelope {
		return "", ErrLimitExceeded
	}
	packed := make([]byte, 0, packedLen)
	packed = append(packed, header...)
	packed = append(packed, nonce...)
	packed = append(packed, ciphertext...)
	return prefix + base64.RawURLEncoding.EncodeToString(packed), nil
}

func checkSealSize(headerLen, plaintextLen, additionalDataLen, limit int) error {
	const gcmOverhead = 16
	const nonceLen = 12
	if additionalDataLen > limit || headerLen > limit-nonceLen-gcmOverhead || plaintextLen > limit-headerLen-nonceLen-gcmOverhead {
		return ErrLimitExceeded
	}
	return nil
}

func parseEnvelope(envelope string, limit int) (header, nonce, ciphertext []byte, err error) {
	if len(envelope) < len(prefix) || envelope[:len(prefix)] != prefix {
		return nil, nil, nil, ErrInvalidEnvelope
	}
	encoded := envelope[len(prefix):]
	if base64.RawURLEncoding.DecodedLen(len(encoded)) > limit {
		return nil, nil, nil, ErrLimitExceeded
	}
	packed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid base64", ErrInvalidEnvelope)
	}
	if len(packed) < 2 || packed[0] != envelopeVersion {
		if len(packed) > 0 && packed[0] != envelopeVersion {
			return nil, nil, nil, ErrUnsupportedVersion
		}
		return nil, nil, nil, ErrInvalidEnvelope
	}
	headerLen := 2
	switch packed[1] {
	case modeKey:
	case modePassword:
		headerLen += 4 + 4 + 1 + saltSize
	default:
		return nil, nil, nil, ErrInvalidEnvelope
	}
	const nonceLen = 12
	if len(packed) < headerLen+nonceLen+16 {
		return nil, nil, nil, ErrInvalidEnvelope
	}
	return packed[:headerLen], packed[headerLen : headerLen+nonceLen], packed[headerLen+nonceLen:], nil
}

func openAEAD(key, header, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, envelopeAAD(header, additionalData))
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func envelopeAAD(header, additionalData []byte) []byte {
	aad := make([]byte, 4+len(header)+len(additionalData))
	binary.BigEndian.PutUint32(aad[:4], uint32(len(header)))
	copy(aad[4:], header)
	copy(aad[4+len(header):], additionalData)
	return aad
}
