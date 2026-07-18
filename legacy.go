package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const legacySaltBase64 = "UfzY+auFk13ShS54P4A6zhnxIHUq3Xtc5hfbS3LHgwYQkXAzQg11+bgUOVrPrmrsfToqh/iGqOolfrX5YeilXiAvopmFo8zNXDkbbRsXqbTrld37vjwsO+l9XT54NyPapTXYNqdC1ts4uhcSjHaDONgjAjgm4+fiXsvJkNJGJ4R3QWu1ekpPRaqrUKdYNeipJ8G4qTIDAj0Zd1rSDFIIAfq5sob9JHPDOd5PhpMZ19VlAPEtDG88IdDGJ5kFGXwNVzNPjC9yl1r6CFFRvFbUxO0B6+JqgsZMCXbj+ofi12gTpc8yohZsU1At0ljkZxh7ioTjpEkUZNUGaMdFaOtKsA=="

type legacyConfig struct {
	salt       []byte
	iterations int
	prefix     string
	encoding   *base64.Encoding
	maxSize    int
}

// LegacyOption configures read-only migration from v1 ciphertext.
type LegacyOption func(*legacyConfig) error

func defaultLegacyConfig() legacyConfig {
	salt, _ := base64.StdEncoding.DecodeString(legacySaltBase64)
	return legacyConfig{salt: salt, iterations: 4096, prefix: "SEC.", encoding: base64.URLEncoding, maxSize: defaultMaxEnvelope}
}

// WithLegacySalt selects the salt used to derive a historical v1 key.
func WithLegacySalt(salt []byte) LegacyOption {
	return func(c *legacyConfig) error {
		if len(salt) == 0 {
			return errors.New("secure: empty legacy salt")
		}
		c.salt = append([]byte(nil), salt...)
		return nil
	}
}

// WithLegacyIterations selects the historical PBKDF2 iteration count.
func WithLegacyIterations(iterations int) LegacyOption {
	return func(c *legacyConfig) error {
		if iterations <= 0 || iterations > 100_000_000 {
			return fmt.Errorf("%w: invalid legacy iteration count", ErrLimitExceeded)
		}
		c.iterations = iterations
		return nil
	}
}

// WithLegacyPrefix selects a custom historical armor prefix.
func WithLegacyPrefix(prefix string) LegacyOption {
	return func(c *legacyConfig) error {
		if prefix == "" {
			return errors.New("secure: empty legacy prefix")
		}
		c.prefix = prefix
		return nil
	}
}

// WithLegacyEncoding selects a custom historical base64 encoding.
func WithLegacyEncoding(encoding *base64.Encoding) LegacyOption {
	return func(c *legacyConfig) error {
		if encoding == nil {
			return errors.New("secure: nil legacy encoding")
		}
		c.encoding = encoding
		return nil
	}
}

// WithLegacyMaxEnvelopeSize bounds decoded historical ciphertext.
func WithLegacyMaxEnvelopeSize(n int) LegacyOption {
	return func(c *legacyConfig) error {
		if n < 32 {
			return ErrLimitExceeded
		}
		c.maxSize = n
		return nil
	}
}

func applyLegacyOptions(opts []LegacyOption) (legacyConfig, error) {
	cfg := defaultLegacyConfig()
	for _, opt := range opts {
		if opt == nil {
			return legacyConfig{}, fmt.Errorf("%w: nil legacy option", ErrInvalidEnvelope)
		}
		if err := opt(&cfg); err != nil {
			return legacyConfig{}, err
		}
	}
	return cfg, nil
}

// OpenLegacy decrypts a v1 SEC. envelope with an already-derived AES-256 key.
func OpenLegacy(envelope string, key []byte, opts ...LegacyOption) ([]byte, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("secure: key must be %d bytes", keySize)
	}
	cfg, err := applyLegacyOptions(opts)
	if err != nil {
		return nil, err
	}
	return openLegacy(envelope, key, cfg)
}

// OpenLegacyWithPassphrase derives the historical PBKDF2-SHA512 key and
// decrypts a v1 SEC. envelope.
func OpenLegacyWithPassphrase(envelope string, passphrase []byte, opts ...LegacyOption) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("secure: empty passphrase")
	}
	cfg, err := applyLegacyOptions(opts)
	if err != nil {
		return nil, err
	}
	key := pbkdf2.Key(passphrase, cfg.salt, cfg.iterations, keySize, sha512.New)
	return openLegacy(envelope, key, cfg)
}

func openLegacy(envelope string, key []byte, cfg legacyConfig) ([]byte, error) {
	envelope = strings.TrimSpace(envelope)
	if !strings.HasPrefix(envelope, cfg.prefix) {
		return nil, ErrInvalidEnvelope
	}
	encoded := envelope[len(cfg.prefix):]
	if cfg.encoding.DecodedLen(len(encoded)) > cfg.maxSize {
		return nil, ErrLimitExceeded
	}
	packed, err := cfg.encoding.DecodeString(encoded)
	if err != nil || len(packed) < 1 {
		return nil, ErrInvalidEnvelope
	}
	dataLen := int(packed[0])
	const nonceSize = 12
	if dataLen > len(packed)-1-nonceSize-16 {
		return nil, ErrInvalidEnvelope
	}
	nonceStart := 1 + dataLen
	nonce := packed[nonceStart : nonceStart+nonceSize]
	ciphertext := packed[nonceStart+nonceSize:]
	additionalData := packed[1:nonceStart]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}
