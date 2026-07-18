package secure

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// EncryptedInt is an instance-bound encrypted JSON integer encoded as a string.
type EncryptedInt struct {
	codec          Codec
	value          int
	allowPlaintext bool
}

// NewEncryptedInt creates a configured encrypted JSON integer.
func NewEncryptedInt(codec Codec, value int, opts ...JSONOption) (EncryptedInt, error) {
	if codec == nil {
		return EncryptedInt{}, ErrUnconfigured
	}
	cfg, err := applyJSONOptions(opts)
	if err != nil {
		return EncryptedInt{}, err
	}
	return EncryptedInt{codec: codec, value: value, allowPlaintext: cfg.allowPlaintext}, nil
}

// Value returns the decrypted integer.
func (i EncryptedInt) Value() int { return i.value }

// Set replaces the plaintext integer.
func (i *EncryptedInt) Set(value int) { i.value = value }

func (i EncryptedInt) String() string { return strconv.Itoa(i.value) }

func (i EncryptedInt) MarshalJSON() ([]byte, error) {
	if i.codec == nil {
		return nil, ErrUnconfigured
	}
	envelope, err := i.codec.Seal([]byte(strconv.Itoa(i.value)), nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

func (i *EncryptedInt) UnmarshalJSON(data []byte) error {
	if i == nil || i.codec == nil {
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
		if !i.allowPlaintext {
			return ErrInvalidEnvelope
		}
		value, err := strconv.Atoi(encoded)
		if err != nil {
			return err
		}
		i.value = value
		return nil
	}
	plaintext, err := i.codec.Open(encoded, nil)
	if err != nil {
		return err
	}
	value, err := strconv.Atoi(string(plaintext))
	if err != nil {
		return ErrInvalidEnvelope
	}
	i.value = value
	return nil
}
