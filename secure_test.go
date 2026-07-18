package secure

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

var testKey = bytes.Repeat([]byte{0x42}, keySize)

func TestCipherRoundTrip(t *testing.T) {
	c, err := NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("secret value")
	aad := []byte("configuration/database")
	envelope, err := c.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(envelope, prefix) {
		t.Fatalf("unexpected envelope: %q", envelope)
	}
	got, err := c.Open(envelope, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
	if _, err := c.Open(envelope, []byte("wrong")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong AAD error = %v", err)
	}

	text, err := c.EncryptString("hello")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.DecryptString(text); err != nil || got != "hello" {
		t.Fatalf("DecryptString() = %q, %v", got, err)
	}
}

func TestCipherCopiesKey(t *testing.T) {
	key := append([]byte(nil), testKey...)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 0xff
	envelope, err := c.EncryptString("copied")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.DecryptString(envelope); err != nil || got != "copied" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestCipherRejectsInvalidConfiguration(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 16), make([]byte, 33)} {
		if _, err := NewCipher(key); err == nil {
			t.Fatalf("accepted %d-byte key", len(key))
		}
	}
	if _, err := NewCipher(testKey, WithMaxEnvelopeSize(1)); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("limit error = %v", err)
	}
	if _, err := NewCipher(testKey, nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("nil option error = %v", err)
	}
	if _, err := NewPasswordCipher(nil); err == nil {
		t.Fatal("accepted empty password")
	}
	weak := Argon2Parameters{Time: 2, Memory: defaultArgonMemory, Threads: defaultArgonThreads}
	if _, err := NewPasswordCipher([]byte("pass"), WithArgon2Parameters(weak)); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("weak Argon2 error = %v", err)
	}
}

func TestEnvelopeTamperingAndValidation(t *testing.T) {
	c, _ := NewCipher(testKey)
	envelope, err := c.EncryptString("tamper me")
	if err != nil {
		t.Fatal(err)
	}
	packed, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, prefix))
	for _, offset := range []int{1, 2, len(packed) - 1} {
		mutated := append([]byte(nil), packed...)
		mutated[offset] ^= 1
		candidate := prefix + base64.RawURLEncoding.EncodeToString(mutated)
		if _, err := c.DecryptString(candidate); err == nil {
			t.Fatalf("tampering at %d was accepted", offset)
		}
	}

	cases := []struct {
		name string
		in   string
		want error
	}{
		{"plaintext", "plain", ErrInvalidEnvelope},
		{"bad base64", prefix + "!", ErrInvalidEnvelope},
		{"empty payload", prefix, ErrInvalidEnvelope},
		{"short payload", prefix + base64.RawURLEncoding.EncodeToString([]byte{2, modeKey}), ErrInvalidEnvelope},
		{"old version", prefix + base64.RawURLEncoding.EncodeToString([]byte{1, modeKey}), ErrUnsupportedVersion},
		{"unknown mode", prefix + base64.RawURLEncoding.EncodeToString([]byte{2, 99}), ErrInvalidEnvelope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.DecryptString(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestEnvelopeLimit(t *testing.T) {
	c, err := NewCipher(testKey, WithMaxEnvelopeSize(80))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(bytes.Repeat([]byte("x"), 80), nil); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Seal error = %v", err)
	}
	oversized := prefix + strings.Repeat("A", 200)
	if _, err := c.Open(oversized, nil); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Open error = %v", err)
	}
	largeAAD := bytes.Repeat([]byte("a"), 81)
	if _, err := c.Seal(nil, largeAAD); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Seal AAD error = %v", err)
	}
	if _, err := c.Open(prefix, largeAAD); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Open AAD error = %v", err)
	}
}

func TestPasswordCipher(t *testing.T) {
	p, err := NewPasswordCipher([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := p.EncryptString("password secret")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.DecryptString(envelope); err != nil || got != "password secret" {
		t.Fatalf("got %q, %v", got, err)
	}
	wrong, _ := NewPasswordCipher([]byte("wrong password"))
	if _, err := wrong.DecryptString(envelope); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong password error = %v", err)
	}
	if _, err := p.DecryptString(envelope); err != nil {
		t.Fatal(err)
	}

	packed, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, prefix))
	packed[2] = 0xff // force an excessive time cost without running Argon2
	bad := prefix + base64.RawURLEncoding.EncodeToString(packed)
	if _, err := p.DecryptString(bad); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("hostile KDF error = %v", err)
	}
}

func TestOpenLegacy(t *testing.T) {
	const envelope = "SEC.AIIPjL0a2HgLgOySAw9fAT6ovih9MfzkMv_pyWmmkA3eBxYbDlLQ"
	passphrase := []byte{0, 0, 0, 0, 0, 0}
	got, err := OpenLegacyWithPassphrase(envelope, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "plain text" {
		t.Fatalf("got %q", got)
	}
	if _, err := OpenLegacyWithPassphrase(envelope, []byte("wrong")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong password error = %v", err)
	}
	if _, err := OpenLegacyWithPassphrase("plain", passphrase); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("plain error = %v", err)
	}
}

func TestLegacyMigrationOptions(t *testing.T) {
	const envelope = "SEC.AIIPjL0a2HgLgOySAw9fAT6ovih9MfzkMv_pyWmmkA3eBxYbDlLQ"
	passphrase := []byte{0, 0, 0, 0, 0, 0}
	cfg := defaultLegacyConfig()
	key := pbkdf2.Key(passphrase, cfg.salt, cfg.iterations, keySize, sha512.New)
	if got, err := OpenLegacy(envelope, key); err != nil || string(got) != "plain text" {
		t.Fatalf("OpenLegacy() = %q, %v", got, err)
	}
	packed, _ := base64.URLEncoding.DecodeString(strings.TrimPrefix(envelope, "SEC."))
	custom := "CUSTOM:" + base64.StdEncoding.EncodeToString(packed)
	got, err := OpenLegacyWithPassphrase(custom, passphrase,
		WithLegacySalt(cfg.salt),
		WithLegacyIterations(4096),
		WithLegacyPrefix("CUSTOM:"),
		WithLegacyEncoding(base64.StdEncoding),
		WithLegacyMaxEnvelopeSize(1024),
	)
	if err != nil || string(got) != "plain text" {
		t.Fatalf("custom legacy = %q, %v", got, err)
	}

	invalid := []LegacyOption{
		WithLegacySalt(nil),
		WithLegacyIterations(0),
		WithLegacyPrefix(""),
		WithLegacyEncoding(nil),
		WithLegacyMaxEnvelopeSize(1),
		nil,
	}
	for i, option := range invalid {
		if _, err := OpenLegacyWithPassphrase(envelope, passphrase, option); err == nil {
			t.Fatalf("invalid option %d accepted", i)
		}
	}
	if _, err := OpenLegacy(envelope, make([]byte, 16)); err == nil {
		t.Fatal("legacy accepted short key")
	}
	if _, err := OpenLegacyWithPassphrase(envelope, nil); err == nil {
		t.Fatal("legacy accepted empty passphrase")
	}
}

func TestPasswordOptionsAndModeSeparation(t *testing.T) {
	p, err := NewPasswordCipher([]byte("password"), WithPasswordMaxEnvelopeSize(1024), WithArgon2Parameters(defaultArgon2Parameters()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPasswordCipher([]byte("password"), nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("nil password option = %v", err)
	}
	c, _ := NewCipher(testKey)
	keyEnvelope, _ := c.EncryptString("key")
	if _, err := p.DecryptString(keyEnvelope); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("password opened key envelope: %v", err)
	}
	passwordEnvelope, _ := p.EncryptString("password")
	if _, err := c.DecryptString(passwordEnvelope); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("key opened password envelope: %v", err)
	}
}

func FuzzOpen(f *testing.F) {
	c, _ := NewCipher(testKey, WithMaxEnvelopeSize(1024))
	f.Add("plain")
	f.Add(prefix)
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = c.Open(input, nil)
	})
}
