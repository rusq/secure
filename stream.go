package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// NewWriter returns a StreamWriter, initialised with the global package key,
// and the provided initialisation vector.  Key can be set with SetKey.
//
// Deprecated: CFB streams do not authenticate ciphertext. Use the authenticated
// stream API in github.com/rusq/secure/v2 for new applications.
func NewWriter(w io.Writer, iv [aes.BlockSize]byte) (*cipher.StreamWriter, error) {
	key := globalKey()
	defer clear(key)
	return NewWriterWithKey(w, key, iv)
}

// NewReader returns a StreamReader, initialised with the global package key,
// and the provided initialisation vector.  Key can be set with SetKey.
//
// Deprecated: CFB streams do not authenticate ciphertext. Use the authenticated
// stream API in github.com/rusq/secure/v2 for new applications.
func NewReader(r io.Reader, iv [aes.BlockSize]byte) (*cipher.StreamReader, error) {
	key := globalKey()
	defer clear(key)
	return NewReaderWithKey(r, key, iv)
}

// NewWriterWithKey returns a new StreamWriter initialised with key and an
// initialisation vector.
//
// Deprecated: CFB streams do not authenticate ciphertext. Use the authenticated
// stream API in github.com/rusq/secure/v2 for new applications.
func NewWriterWithKey(w io.Writer, key []byte, iv [aes.BlockSize]byte) (*cipher.StreamWriter, error) {
	if w == nil {
		return nil, errors.New("secure: nil writer")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv[:])
	return &cipher.StreamWriter{S: stream, W: w}, nil
}

// NewReaderWithKey returns a new StreamReader initialised with key and an
// initialisation vector.
//
// Deprecated: CFB streams do not authenticate ciphertext. Use the authenticated
// stream API in github.com/rusq/secure/v2 for new applications.
func NewReaderWithKey(r io.Reader, key []byte, iv [aes.BlockSize]byte) (*cipher.StreamReader, error) {
	if r == nil {
		return nil, errors.New("secure: nil reader")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, iv[:])
	return &cipher.StreamReader{S: stream, R: r}, nil
}
