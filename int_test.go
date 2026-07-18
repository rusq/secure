package secure

import (
	"errors"
	"math"
	"testing"
)

func TestInt_MarshalUnmarshalJSON(t *testing.T) {
	s := newTestKeySentinel()
	defer s.Reset()

	testcases := []int{123, -1, math.MaxInt}
	for _, tc := range testcases {
		val := Int(tc)
		data, err := val.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var got Int
		if err := got.UnmarshalJSON(data); err != nil {
			t.Fatal(err)
		}
		if got != val {
			t.Fatalf("round trip = %d, want %d", got, val)
		}
	}
}

func TestIntUnmarshalCompatibilityAndErrors(t *testing.T) {
	s := newTestKeySentinel()
	defer s.Reset()

	for _, input := range []string{`123`, `"123"`} {
		var got Int
		if err := got.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("UnmarshalJSON(%q): %v", input, err)
		}
		if got != 123 {
			t.Fatalf("UnmarshalJSON(%q) = %d", input, got)
		}
	}

	var empty Int = 42
	if err := empty.UnmarshalJSON([]byte(`""`)); err != nil || empty != 0 {
		t.Fatalf("empty integer = %d, %v", empty, err)
	}
	var invalid Int
	if err := invalid.UnmarshalJSON([]byte(`"not-an-integer"`)); err == nil {
		t.Fatal("invalid plaintext integer was accepted")
	}
	if err := invalid.UnmarshalJSON([]byte(`"SEC.invalid"`)); err == nil || errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("invalid encrypted integer error = %v", err)
	}
}

func FuzzMarshalUnmarshalJSON(f *testing.F) {
	s := newTestKeySentinel()
	defer s.Reset()

	testcases := []int{123, -1, math.MaxInt}
	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, input int) {
		val := Int(input)
		data, err := val.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var got Int
		if err := got.UnmarshalJSON(data); err != nil {
			t.Fatal(err)
		}
		if got != val {
			t.Fatalf("round trip = %d, want %d", got, val)
		}
	})
}
