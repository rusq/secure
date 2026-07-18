package secure

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Int is an encrypted integer.
type Int int

func (ei Int) String() string {
	return strconv.Itoa(int(ei))
}

func (ei Int) MarshalJSON() ([]byte, error) {
	data, err := Encrypt(ei.String())
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

func (ei *Int) UnmarshalJSON(b []byte) error {
	b = decodeJSONString(b)
	if len(b) == 0 {
		*ei = 0
		return nil
	}
	pt, err := Decrypt(string(b))
	if err != nil {
		if err == ErrNotEncrypted {
			val, err := strconv.Atoi(string(b))
			if err != nil {
				return err
			}
			*ei = Int(val)
			return nil
		}
		return fmt.Errorf("%w, while decrypting: %q", err, string(b))
	}
	val, err := strconv.Atoi(pt)
	if err != nil {
		return err
	}
	*ei = Int(val)
	return nil
}
