package secure

import (
	"bytes"
	"encoding/json"
	"errors"
)

type jsonConfig struct {
	allowPlaintext bool
}

// JSONOption configures encrypted JSON values.
type JSONOption func(*jsonConfig)

// WithPlaintextJSONMigration permits a JSON value to accept plaintext input.
// Values are still encrypted the next time they are marshaled.
func WithPlaintextJSONMigration() JSONOption {
	return func(c *jsonConfig) { c.allowPlaintext = true }
}

// EncryptedString is an instance-bound encrypted JSON string.
type EncryptedString struct {
	codec          Codec
	value          string
	allowPlaintext bool
}

// NewEncryptedString creates a configured encrypted JSON string.
func NewEncryptedString(codec Codec, value string, opts ...JSONOption) (EncryptedString, error) {
	if codec == nil {
		return EncryptedString{}, ErrUnconfigured
	}
	cfg, err := applyJSONOptions(opts)
	if err != nil {
		return EncryptedString{}, err
	}
	return EncryptedString{codec: codec, value: value, allowPlaintext: cfg.allowPlaintext}, nil
}

func applyJSONOptions(opts []JSONOption) (jsonConfig, error) {
	var cfg jsonConfig
	for _, opt := range opts {
		if opt == nil {
			return jsonConfig{}, errors.New("secure: nil JSON option")
		}
		opt(&cfg)
	}
	return cfg, nil
}

// Value returns the decrypted value.
func (s EncryptedString) Value() string { return s.value }

// Set replaces the plaintext value.
func (s *EncryptedString) Set(value string) { s.value = value }

func (s EncryptedString) String() string { return s.value }

func (s EncryptedString) MarshalJSON() ([]byte, error) {
	if s.codec == nil {
		return nil, ErrUnconfigured
	}
	envelope, err := s.codec.Seal([]byte(s.value), nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

func (s *EncryptedString) UnmarshalJSON(data []byte) error {
	if s == nil || s.codec == nil {
		return ErrUnconfigured
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return ErrInvalidEnvelope
	}
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	if len(encoded) < len(prefix) || encoded[:len(prefix)] != prefix {
		if !s.allowPlaintext {
			return ErrInvalidEnvelope
		}
		s.value = encoded
		return nil
	}
	plaintext, err := s.codec.Open(encoded, nil)
	if err != nil {
		return err
	}
	s.value = string(plaintext)
	return nil
}
