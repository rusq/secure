package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

// NewWriter returns a StreamWriter, initialised with the global package key,
// and the provided initialisation vector.  Key can be set with SetKey.
func NewWriter(w io.Writer, iv [aes.BlockSize]byte) (*cipher.StreamWriter, error) {
	return NewWriterWithKey(w, gKey, iv)
}

// NewWriter returns a StreamReader, initialised with the global package key,
// and the provided initialisation vector.  Key can be set with SetKey.
func NewReader(r io.Reader, iv [aes.BlockSize]byte) (*cipher.StreamReader, error) {
	return NewReaderWithKey(r, gKey, iv)
}

// NewWriterWithKey returns a new StreamWriter initialised with key and an
// initialisation vector.
func NewWriterWithKey(w io.Writer, key []byte, iv [aes.BlockSize]byte) (*cipher.StreamWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv[:])
	return &cipher.StreamWriter{S: stream, W: w}, nil
}

// NewReaderWithKey returns a new StreamReader initialised with key and an
// initialisation vector.
func NewReaderWithKey(r io.Reader, key []byte, iv [aes.BlockSize]byte) (*cipher.StreamReader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, iv[:])
	return &cipher.StreamReader{S: stream, R: r}, nil
}
