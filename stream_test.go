package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
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
	rand.Read(randomness)

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
	_, err = r.Read(output)
	if err != nil {
		t.Errorf("output read error: %s", err)
	}

	// compare
	if !bytes.Equal(randomness, output) {
		t.Fatal("input and output data is different")
	}
}
