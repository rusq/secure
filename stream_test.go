package secure

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestAuthenticatedStreamRoundTrip(t *testing.T) {
	c, _ := NewCipher(testKey)
	for _, size := range []int{0, 1, streamChunkSize - 1, streamChunkSize, streamChunkSize + 1, 2*streamChunkSize + 17} {
		t.Run(string(rune(size)), func(t *testing.T) {
			input := bytes.Repeat([]byte{byte(size)}, size)
			var encrypted bytes.Buffer
			w, err := c.NewEncryptWriter(&encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(input); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := c.NewDecryptReader(bytes.NewReader(encrypted.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, input) {
				t.Fatalf("got %d bytes, want %d", len(got), len(input))
			}
		})
	}
}

func TestStreamDetectsTamperingAndTruncation(t *testing.T) {
	c, _ := NewCipher(testKey)
	var encrypted bytes.Buffer
	w, _ := c.NewEncryptWriter(&encrypted)
	_, _ = w.Write([]byte("stream secret"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	original := encrypted.Bytes()

	tampered := append([]byte(nil), original...)
	tampered[len(tampered)-1] ^= 1
	r, err := c.NewDecryptReader(bytes.NewReader(tampered))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}

	for _, cut := range []int{1, 5, len(original) - 1} {
		r, err := c.NewDecryptReader(bytes.NewReader(original[:cut]))
		if err == nil {
			_, err = io.ReadAll(r)
		}
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("cut %d error = %v", cut, err)
		}
	}
}

func TestStreamWrongKeyAndClose(t *testing.T) {
	c, _ := NewCipher(testKey)
	var encrypted bytes.Buffer
	w, _ := c.NewEncryptWriter(&encrypted)
	_, _ = w.Write([]byte("data"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := w.Write([]byte("late")); err == nil {
		t.Fatal("write after close succeeded")
	}

	wrongKey := bytes.Repeat([]byte{0x99}, keySize)
	wrong, _ := NewCipher(wrongKey)
	r, err := wrong.NewDecryptReader(bytes.NewReader(encrypted.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key error = %v", err)
	}
}

func TestPasswordStream(t *testing.T) {
	p, _ := NewPasswordCipher([]byte("stream password"))
	var encrypted bytes.Buffer
	w, err := p.NewEncryptWriter(&encrypted)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "password stream")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := p.NewDecryptReader(bytes.NewReader(encrypted.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "password stream" {
		t.Fatalf("got %q, %v", got, err)
	}
}

type shortWriter struct{ remaining int }

func (w *shortWriter) Write(p []byte) (int, error) {
	if w.remaining == 0 {
		return 0, io.ErrClosedPipe
	}
	n := min(len(p), w.remaining)
	w.remaining -= n
	return n, nil
}

func TestStreamPropagatesWriteFailure(t *testing.T) {
	c, _ := NewCipher(testKey)
	w, err := c.NewEncryptWriter(&shortWriter{remaining: len(streamMagic) + 1 + saltSize + 10})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(bytes.Repeat([]byte("x"), streamChunkSize))
	if err := w.Close(); err == nil {
		t.Fatal("expected write failure")
	}
}

func TestStreamRejectsInvalidHeadersAndRecords(t *testing.T) {
	c, _ := NewCipher(testKey)
	if _, err := c.NewEncryptWriter(nil); err == nil {
		t.Fatal("accepted nil writer")
	}
	if _, err := c.NewDecryptReader(nil); err == nil {
		t.Fatal("accepted nil reader")
	}
	if _, err := c.NewDecryptReader(bytes.NewReader([]byte("short"))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short header error = %v", err)
	}
	badHeader := append([]byte(streamMagic), modePassword)
	badHeader = append(badHeader, make([]byte, 9+saltSize)...)
	if _, err := c.NewDecryptReader(bytes.NewReader(badHeader)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("wrong mode error = %v", err)
	}

	var encrypted bytes.Buffer
	w, _ := c.NewEncryptWriter(&encrypted)
	_, _ = w.Write([]byte("record"))
	_ = w.Close()
	headerLen := len(streamMagic) + 1 + saltSize
	for _, mutate := range []func([]byte){
		func(b []byte) { b[headerLen] = 0xff },
		func(b []byte) { b[headerLen+4] = 0x80 },
		func(b []byte) { b[headerLen+4] = streamFinal },
	} {
		data := append([]byte(nil), encrypted.Bytes()...)
		mutate(data)
		r, err := c.NewDecryptReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(r); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("invalid record error = %v", err)
		}
	}
}

func TestPasswordStreamRejectsHostileParameters(t *testing.T) {
	p, _ := NewPasswordCipher([]byte("password"))
	if _, err := p.NewEncryptWriter(nil); err == nil {
		t.Fatal("accepted nil writer")
	}
	header := append([]byte(streamMagic), modePassword)
	params := make([]byte, 9)
	params[0] = 0xff
	header = append(header, params...)
	header = append(header, make([]byte, saltSize)...)
	if _, err := p.NewDecryptReader(bytes.NewReader(header)); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("hostile parameters error = %v", err)
	}
}
