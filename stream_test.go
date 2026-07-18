package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

var _ = SetPassphrase([]byte{0})

func TestStreamReadWriter(t *testing.T) {
	const randomBufSz = 512000

	// initialise the initialisation vector with randomness
	var testIV [aes.BlockSize]byte
	if _, err := rand.Read(testIV[:]); err != nil {
		t.Fatal(err)
	}
	key, err := DeriveKey([]byte("unittesting"), keySz)
	if err != nil {
		t.Fatal(err)
	}

	// generate test data
	randomness := make([]byte, randomBufSz)
	if _, err := rand.Read(randomness); err != nil {
		t.Fatal(err)
	}

	// write it to the encryption buffer
	var buf bytes.Buffer
	w, err := NewWriterWithKey(&buf, key, testIV)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = w.Write(randomness); err != nil {
		t.Errorf("write error: %s", err)
	}

	// read data into output from buffer
	r, err := NewReaderWithKey(&buf, key, testIV)
	if err != nil {
		t.Fatal(err)
	}

	output := make([]byte, len(randomness))
	_, err = io.ReadFull(r, output)
	if err != nil {
		t.Errorf("output read error: %s", err)
	}

	// compare
	if !bytes.Equal(randomness, output) {
		t.Fatal("input and output data is different")
	}
}

func TestStreamRejectsNilEndpoints(t *testing.T) {
	var iv [aes.BlockSize]byte
	key := bytes.Repeat([]byte{0x42}, keySz)
	if _, err := NewWriterWithKey(nil, key, iv); err == nil {
		t.Fatal("NewWriterWithKey accepted a nil writer")
	}
	if _, err := NewReaderWithKey(nil, key, iv); err == nil {
		t.Fatal("NewReaderWithKey accepted a nil reader")
	}
	if err := SetGlobalKey(key); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(nil, iv); err == nil {
		t.Fatal("NewWriter accepted a nil writer")
	}
	if _, err := NewReader(nil, iv); err == nil {
		t.Fatal("NewReader accepted a nil reader")
	}

	if _, err := NewWriterWithKey(io.Discard, nil, iv); err == nil || errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("invalid key error = %v", err)
	}
	if _, err := NewReaderWithKey(bytes.NewReader(nil), nil, iv); err == nil {
		t.Fatal("NewReaderWithKey accepted an invalid key")
	}
}
