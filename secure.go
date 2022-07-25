// Package secure provides simple convenience encryption and decryption
// functions.
//
// It should not be used to encrypt critical information in open source
// projects, where the salt might be known to attaker.
//
// It uses the standard Go runtime AES-256 block cipher with GCM.
//
// Encryption key is a 256-bit value (32 bytes).
//
// The default "Salt" is a fixed 256 byte array of pseudo-random values, taken
// from /dev/urandom.
//
// Encryption key is derived in the following manner:
//
//   1. Repeat bytes of the passphrase to form 32 bytes of the Key
//   2. Take the first byte of the passphrase and use it for the value of the
//      Offset in the salt array.
//   3. For each byte of the key, `i` being the counter, and `pass` being the
//      passphrase:
//
//         key[i] = pass[i%len(pass)] ^ salt[(i+startOffset)%SaltSz]
//
// Then the plain text is encrypted with the Key using AES-256 in GCM and
// signed together with additional data.
//
// Then additional data, nonce and ciphertext are packed into the following
// sequence of bytes:
//
//   |_|__...__|_________|__...__|
//    ^    ^        ^        ^
//    |    |        |        +- ciphertext, n bytes.
//    |    |        +---------- nonce, (nonceSz bytes)
//    |    +------------------- additinal data, m bytes, (maxDataSz bytes),
//    +------------------------ additional data length value (adlSz bytes).
//
// After this, packed byte sequence is armoured with base64 and the signature
// prefix added to it to distinct it from the plain text.
package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	nonceSz   = 12               // bytes, nonce sz
	keyBits   = 256              // encryption gKey size.
	keySz     = keyBits / 8      // bytes, gKey size
	adlSz     = 1                // bytes, size of additional data length field
	maxDataSz = 1<<(adlSz*8) - 1 // bytes, max additional data size (this is the maximum that can fit into (adlSz) bytes)
	// SaltSz is the size of the Salt array.
	SaltSz = keySz * 8
)

var (
	// used to identify encrypted strings
	signature = "SEC."
	// salt will be used to XOR the gKey which we generate by padding the
	// passphrase.  It is advised that caller sets their own salt (BYO) with
	// SetSalt.
	salt = [SaltSz]byte{
		0x51, 0xfc, 0xd8, 0xf9, 0xab, 0x85, 0x93, 0x5d, 0xd2, 0x85, 0x2e, 0x78,
		0x3f, 0x80, 0x3a, 0xce, 0x19, 0xf1, 0x20, 0x75, 0x2a, 0xdd, 0x7b, 0x5c,
		0xe6, 0x17, 0xdb, 0x4b, 0x72, 0xc7, 0x83, 0x06, 0x10, 0x91, 0x70, 0x33,
		0x42, 0x0d, 0x75, 0xf9, 0xb8, 0x14, 0x39, 0x5a, 0xcf, 0xae, 0x6a, 0xec,
		0x7d, 0x3a, 0x2a, 0x87, 0xf8, 0x86, 0xa8, 0xea, 0x25, 0x7e, 0xb5, 0xf9,
		0x61, 0xe8, 0xa5, 0x5e, 0x20, 0x2f, 0xa2, 0x99, 0x85, 0xa3, 0xcc, 0xcd,
		0x5c, 0x39, 0x1b, 0x6d, 0x1b, 0x17, 0xa9, 0xb4, 0xeb, 0x95, 0xdd, 0xfb,
		0xbe, 0x3c, 0x2c, 0x3b, 0xe9, 0x7d, 0x5d, 0x3e, 0x78, 0x37, 0x23, 0xda,
		0xa5, 0x35, 0xd8, 0x36, 0xa7, 0x42, 0xd6, 0xdb, 0x38, 0xba, 0x17, 0x12,
		0x8c, 0x76, 0x83, 0x38, 0xd8, 0x23, 0x02, 0x38, 0x26, 0xe3, 0xe7, 0xe2,
		0x5e, 0xcb, 0xc9, 0x90, 0xd2, 0x46, 0x27, 0x84, 0x77, 0x41, 0x6b, 0xb5,
		0x7a, 0x4a, 0x4f, 0x45, 0xaa, 0xab, 0x50, 0xa7, 0x58, 0x35, 0xe8, 0xa9,
		0x27, 0xc1, 0xb8, 0xa9, 0x32, 0x03, 0x02, 0x3d, 0x19, 0x77, 0x5a, 0xd2,
		0x0c, 0x52, 0x08, 0x01, 0xfa, 0xb9, 0xb2, 0x86, 0xfd, 0x24, 0x73, 0xc3,
		0x39, 0xde, 0x4f, 0x86, 0x93, 0x19, 0xd7, 0xd5, 0x65, 0x00, 0xf1, 0x2d,
		0x0c, 0x6f, 0x3c, 0x21, 0xd0, 0xc6, 0x27, 0x99, 0x05, 0x19, 0x7c, 0x0d,
		0x57, 0x33, 0x4f, 0x8c, 0x2f, 0x72, 0x97, 0x5a, 0xfa, 0x08, 0x51, 0x51,
		0xbc, 0x56, 0xd4, 0xc4, 0xed, 0x01, 0xeb, 0xe2, 0x6a, 0x82, 0xc6, 0x4c,
		0x09, 0x76, 0xe3, 0xfa, 0x87, 0xe2, 0xd7, 0x68, 0x13, 0xa5, 0xcf, 0x32,
		0xa2, 0x16, 0x6c, 0x53, 0x50, 0x2d, 0xd2, 0x58, 0xe4, 0x67, 0x18, 0x7b,
		0x8a, 0x84, 0xe3, 0xa4, 0x49, 0x14, 0x64, 0xd5, 0x06, 0x68, 0xc7, 0x45,
		0x68, 0xeb, 0x4a, 0xb0,
	}
)

var (
	ErrNotEncrypted    = errors.New("string not encrypted")
	ErrNoEncryptionKey = errors.New("no encryption gKey")
	ErrDataOverflow    = errors.New("additional data overflow")
	ErrInvalidKeySz    = errors.New("invalid Key size")
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

var gKey []byte

// setGlobalKey sets the encryption gKey globally.
func setGlobalKey(k []byte) error {
	if len(k) != keySz {
		return ErrInvalidKeySz
	}
	gKey = k
	return nil
}

func SetPassphrase(b []byte) error {
	k, err := deriveKey(b)
	if err != nil {
		return err
	}
	return setGlobalKey(k)
}

// deriveKey interpolates the passphrase value to the gKey size and xors it
// with salt.
func deriveKey(pass []byte) ([]byte, error) {
	if len(pass) == 0 {
		return nil, errors.New("empty passphrase")
	}
	if len(pass) > keySz {
		return nil, errors.New("passphrase is too big")
	}

	var key = make([]byte, keySz)
	var startOffset = int(pass[0]) // starting offset in salt is the first byte of the password
	if SaltSz <= startOffset {
		// this should never happen
		panic("start offset overflows the salt array size")
	}

	for i := range key {
		key[i] = pass[i%len(pass)] ^ salt[(i+startOffset)%SaltSz]
	}
	return key, nil
}

// Encrypt encrypts the plain text password to use in the configuration file
// with the gKey generated by KeyFn.
func Encrypt(plaintext string) (string, error) {
	return encrypt(plaintext, gKey, nil)
}

// Decrypt attempts to decrypt the string and return the password.
// In case s is not an encrypted string, ErrNotEncrypted returned along with
// original string.
func Decrypt(s string) (string, error) {
	return decrypt(s, gKey)
}

// EncryptWithPassphrase encrypts plaintext with the provided passphrase
func EncryptWithPassphrase(plaintext string, passphrase []byte) (string, error) {
	key, err := deriveKey(passphrase)
	if err != nil {
		return "", err
	}
	return encrypt(plaintext, key, nil)
}

// DecryptWithPassphrase attempts to descrypt string with the provided MAC
// address.
func DecryptWithPassphrase(s string, passphrase []byte) (string, error) {
	key, err := deriveKey(passphrase)
	if err != nil {
		return "", err
	}
	return decrypt(s, key)
}

// Encrypt encrypts the plain text password to use in the configuration file.
func encrypt(plaintext string, key []byte, additionalData []byte) (string, error) {
	if len(key) == 0 {
		return "", ErrNoEncryptionKey
	}
	if len(key) != keySz {
		return "", ErrInvalidKeySz
	}
	if len(plaintext) == 0 {
		return "", errors.New("nothing to encrypt")
	}
	if len(additionalData) > maxDataSz {
		return "", fmt.Errorf("size of additional data can't exceed %d B", maxDataSz)
	}

	gcm, err := initGCM(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSz)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), additionalData)

	// return signature + base64.StdEncoding.EncodeToString(data), nil
	packed, err := pack(ciphermsg{nonce, ciphertext, additionalData})
	if err != nil {
		return "", err
	}

	return armor(packed), nil
}

// initGCM initialises the Galois/Counter Mode
func initGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func pack(cm ciphermsg) ([]byte, error) {
	if len(cm.nonce) == 0 {
		return nil, errors.New("pack: empty nonce")
	}
	if len(cm.ciphertext) == 0 {
		return nil, errors.New("pack: no ciphertext")
	}
	dataLen := len(cm.additionalData)
	if dataLen > maxDataSz {
		return nil, ErrDataOverflow
	}

	packed := make([]byte, nonceSz+len(cm.ciphertext)+1+dataLen)
	packed[0] = byte(dataLen)
	if dataLen > 0 {
		copy(packed[adlSz:], cm.additionalData)
	}
	copy(packed[adlSz+dataLen:], cm.nonce)
	copy(packed[adlSz+dataLen+nonceSz:], cm.ciphertext)

	return packed, nil
}

func armor(packed []byte) string {
	return signature + base64.StdEncoding.EncodeToString(packed)
}

func unarmor(s string) ([]byte, error) {
	sigSz := len(signature)
	s = strings.TrimSpace(s)
	if len(s) < sigSz || s[0:sigSz] != signature {
		return nil, ErrNotEncrypted
	}
	packed, err := base64.StdEncoding.DecodeString(s[sigSz:])
	if err != nil {
		return nil, err
	}
	return packed, nil
}

type ciphermsg struct {
	nonce          []byte
	ciphertext     []byte
	additionalData []byte
}

func unpack(packed []byte) (*ciphermsg, error) {
	if len(packed) == 0 {
		return nil, errors.New("unpack: empty input")
	}
	var (
		dataLen   = int(packed[0])
		payloadSz = len(packed) - adlSz - nonceSz // payload is data + ct size
	)
	if dataLen > payloadSz || payloadSz-dataLen == 0 {
		return nil, &CorruptError{packed}
	}
	cm := &ciphermsg{
		nonce:      packed[adlSz+dataLen : adlSz+dataLen+nonceSz],
		ciphertext: packed[adlSz+dataLen+nonceSz:],
	}
	if dataLen > 0 {
		cm.additionalData = packed[adlSz : adlSz+dataLen]
	}
	return cm, nil
}

func decrypt(s string, key []byte) (string, error) {
	packed, err := unarmor(s)
	if err != nil {
		if err == ErrNotEncrypted {
			return s, err
		}
		return "", err // other error
	}
	if len(key) == 0 {
		return "", ErrNoEncryptionKey
	}
	cm, err := unpack(packed)
	if err != nil {
		return "", err
	}
	aesgcm, err := initGCM(key)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, cm.nonce, cm.ciphertext, cm.additionalData)
	if err != nil {
		return "", &CipherError{err}
	}
	return string(plaintext), nil
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

// SetSignature allows to set package-wide signature, that is used to identify
// encrypted strings.
func SetSignature(s string) {
	if len(s) == 0 {
		panic("signature can't be empty")
	}
	signature = s
}

// SetSalt allows to set package-wide salt that will be used with every call.
// Salt should be a random set of bytes, but should remain the same across the
// calls and application restarts, so it should be generated in some
// deterministic way.  It would not be possible to decrypt cipher text with
// different salt.
//
// IT IS STRONGLY ADVISED TO USE YOUR OWN SALT.
//
func SetSalt(sa [SaltSz]byte) {
	salt = sa
}