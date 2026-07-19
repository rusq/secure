package secure

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// String is a type of encrypted string.  Surprise.
type String string

func (es String) String() string {
	return string(es)
}

func (es String) MarshalJSON() ([]byte, error) {
	if len(es) == 0 {
		return json.Marshal("")
	}
	data, err := Encrypt(string(es))
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

func (es *String) UnmarshalJSON(b []byte) error {
	b = decodeJSONString(b)
	if len(b) == 0 {
		*es = ""
		return nil
	}
	pt, err := Decrypt(string(b))
	if err != nil {
		if err == ErrNotEncrypted {
			*es = String(b)
			return nil
		}
		return fmt.Errorf("%w, while decrypting: %q", err, string(b))
	}
	*es = String(pt)
	return nil
}

func decodeJSONString(b []byte) []byte {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		// Preserve v0.1's handling: String stores the literal text "null"
		// while Int passes it to strconv.Atoi and returns an error.
		return bytes.Trim(b, `"`)
	}
	var value string
	if err := json.Unmarshal(b, &value); err == nil {
		return []byte(value)
	}
	// Preserve v0.1's permissive handling for callers that invoke
	// UnmarshalJSON directly with unquoted input.
	return bytes.Trim(b, `"`)
}
