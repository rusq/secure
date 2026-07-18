package secure

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestEncryptedStringJSON(t *testing.T) {
	c, _ := NewCipher(testKey)
	secret, err := NewEncryptedString(c, "quote: \" and slash: \\")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := NewEncryptedString(c, "")
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Value() != secret.Value() {
		t.Fatalf("got %q", decoded.Value())
	}
	decoded.Set("changed")
	if decoded.String() != "changed" {
		t.Fatalf("Set failed: %q", decoded.String())
	}
}

func TestEncryptedStringRejectsPlaintext(t *testing.T) {
	c, _ := NewCipher(testKey)
	strict, _ := NewEncryptedString(c, "")
	if err := json.Unmarshal([]byte(`"plain"`), &strict); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("plaintext error = %v", err)
	}
	if err := json.Unmarshal([]byte(`null`), &strict); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("null error = %v", err)
	}
	if err := json.Unmarshal([]byte(`123`), &strict); err == nil {
		t.Fatal("numeric JSON accepted")
	}

	migration, _ := NewEncryptedString(c, "", WithPlaintextJSONMigration())
	if err := json.Unmarshal([]byte(`"plain"`), &migration); err != nil {
		t.Fatal(err)
	}
	if migration.Value() != "plain" {
		t.Fatalf("got %q", migration.Value())
	}
	data, err := json.Marshal(migration)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == `"plain"` {
		t.Fatal("migration value was not encrypted")
	}
}

func TestEncryptedStringUnconfigured(t *testing.T) {
	var value EncryptedString
	if _, err := json.Marshal(value); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("marshal error = %v", err)
	}
	if err := json.Unmarshal([]byte(`"x"`), &value); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("unmarshal error = %v", err)
	}
	if _, err := NewEncryptedString(nil, ""); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("constructor error = %v", err)
	}
	if _, err := NewEncryptedString(&Cipher{}, "", nil); err == nil {
		t.Fatal("accepted nil JSON option")
	}
}
