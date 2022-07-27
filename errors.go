package secure

import (
	"bytes"
	"errors"
)

var (
	ErrNotEncrypted    = errors.New("string not encrypted")
	ErrNoEncryptionKey = errors.New("no encryption gKey")
	ErrDataOverflow    = errors.New("additional data overflow")
	ErrInvalidKeySz    = errors.New("invalid key size, len(key)%8!=0")
)

// CipherError indicates that there was an error during decrypting of
// ciphertext.
type CipherError struct {
	Err error
}

func (e *CipherError) Error() string {
	return e.Err.Error()
}

func (e *CipherError) Unwrap() error {
	return e.Err
}

func (e *CipherError) Is(target error) bool {
	t, ok := target.(*CipherError)
	if !ok {
		return false
	}
	return e.Err.Error() == t.Err.Error()
}

type CorruptError struct {
	Value []byte
}

func (e *CorruptError) Error() string {
	return "corrupt packed data"
}

func (e *CorruptError) Is(target error) bool {
	t, ok := target.(*CorruptError)
	if !ok {
		return false
	}
	return bytes.Equal(t.Value, e.Value)
}

// IsDecipherError returns true if there was a decryption error or corrupt data
// error and false if it's a different kind of error.
func IsDecipherError(err error) bool {
	switch err.(type) {
	case *CipherError, *CorruptError:
		return true
	}
	return false
}
