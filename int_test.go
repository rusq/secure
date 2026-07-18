package secure

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
)

func TestEncryptedIntJSON(t *testing.T) {
	c, _ := NewCipher(testKey)
	for _, input := range []int{0, -1, 42, math.MaxInt} {
		value, _ := NewEncryptedInt(c, input)
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := NewEncryptedInt(c, 0)
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Value() != input {
			t.Fatalf("got %d, want %d", decoded.Value(), input)
		}
		decoded.Set(7)
		if decoded.String() != "7" {
			t.Fatalf("Set failed: %q", decoded.String())
		}
	}
}

func TestEncryptedIntMigrationAndValidation(t *testing.T) {
	c, _ := NewCipher(testKey)
	strict, _ := NewEncryptedInt(c, 0)
	if err := json.Unmarshal([]byte(`"12"`), &strict); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("strict error = %v", err)
	}
	migration, _ := NewEncryptedInt(c, 0, WithPlaintextJSONMigration())
	if err := json.Unmarshal([]byte(`"-12"`), &migration); err != nil || migration.Value() != -12 {
		t.Fatalf("migration = %d, %v", migration.Value(), err)
	}
	if err := json.Unmarshal([]byte(`"bad"`), &migration); err == nil {
		t.Fatal("accepted invalid integer")
	}
	if err := json.Unmarshal([]byte(`null`), &migration); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("null error = %v", err)
	}
	if _, err := NewEncryptedInt(nil, 0); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("constructor error = %v", err)
	}
	if _, err := NewEncryptedInt(c, 0, nil); err == nil {
		t.Fatal("accepted nil JSON option")
	}
	var unconfigured EncryptedInt
	if _, err := json.Marshal(unconfigured); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("marshal error = %v", err)
	}
	if err := json.Unmarshal([]byte(`"1"`), &unconfigured); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("unmarshal error = %v", err)
	}
	invalidEnvelope, _ := c.EncryptString("not an integer")
	if err := json.Unmarshal([]byte(`"`+invalidEnvelope+`"`), &strict); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("invalid encrypted integer error = %v", err)
	}
}
