package secure

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"reflect"
	"testing"
)

const (
	encryptedPlainText = "SEC.AIIPjL0a2HgLgOySAw9fAT6ovih9MfzkMv_pyWmmkA3eBxYbDlLQ"
)

var testPassphrase = []byte{0, 0, 0, 0, 0, 0}

func TestEncryptPlainText(t *testing.T) {
	out, err := EncryptWithPassphrase("plain text", testPassphrase)
	if err != nil {
		fmt.Println("brokeh:", err)
		return
	}
	t.Log(out)
	// Output:
}

func testNonce(b byte) []byte {
	var n = make([]byte, nonceSz)
	for i := range n {
		n[i] = b
	}
	return n
}

func Test_deriveKey(t *testing.T) {
	type args struct {
		pass []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"zero", args{testPassphrase},
			[]byte{0x3c, 0x23, 0x9f, 0xe6, 0x3c, 0x15, 0xe2, 0x58, 0xc3, 0x57, 0xed, 0xf6, 0xe1, 0xed, 0x88, 0xb0, 0xc1, 0xa1, 0x49, 0xdd, 0xef, 0xb8, 0x56, 0x6f, 0x3e, 0xb2, 0x76, 0x2a, 0x8, 0xb8, 0x9, 0x16},
			false,
		},
		{"offset 1",
			args{[]byte{1, 0, 0, 0, 0, 0}},
			[]byte{0xad, 0x7, 0xde, 0xbf, 0x54, 0xef, 0x32, 0xee, 0xee, 0xda, 0xb3, 0x3f, 0x1, 0x5f, 0x34, 0xd, 0x20, 0x63, 0x31, 0x67, 0x73, 0xd8, 0xb8, 0x77, 0xba, 0x94, 0xa5, 0x79, 0xaf, 0x26, 0xc2, 0xd0},
			false,
		},
		{"empty pass", args{nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveKey(tt.args.pass, keySz)
			if (err != nil) != tt.wantErr {
				t.Errorf("deriveKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("deriveKey() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// to reset it's value.
type keySentinel struct {
	oldKey []byte
}

// newKeySentinel sets the global gKey to the specified value.  Call Reset() on
// the sentinel to reset the initial variable value.
func newKeySentinel(k []byte) keySentinel {
	m := keySentinel{gKey}
	if err := SetGlobalKey(k); err != nil {
		panic(err)
	}
	return m
}

// Reset resets the old value of KeyFromHwAddr
func (m keySentinel) Reset() {
	if err := SetGlobalKey(m.oldKey); err != nil {
		log.Printf("this is ok: %s", err)
	}
}

// newTestKeySentinel sets the gKey to test password
func newTestKeySentinel() keySentinel {
	k, err := DeriveKey(testPassphrase, keySz)
	if err != nil {
		panic(err)
	}
	return newKeySentinel(k)
}

func Test_Encryption(t *testing.T) {
	const wantPT = "plain text"

	m := newTestKeySentinel()
	defer m.Reset()

	key, err := DeriveKey(testPassphrase, keySz)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := encrypt(wantPT, key, []byte("123"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ct)
	pt, err := decrypt(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wantPT, pt) {
		t.Errorf("before/after pt doesn't match: want=%q, got=%q", wantPT, pt)
	}
}

func Test_EncryptDecryptWithPassphrase(t *testing.T) {
	const wantPT = "plain text"

	ct, err := EncryptWithPassphrase(wantPT, []byte("1234567890"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ct)
	pt, err := DecryptWithPassphrase(ct+"     ", []byte("1234567890"))
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(wantPT, pt) {
		t.Errorf("before/after pt doesn't match: want=%q, got=%q", wantPT, pt)
	}

	// trying to decrypt with different passphrase should return error
	pt, err = DecryptWithPassphrase(ct, []byte("11:22:33:44:55:66"))
	if err == nil {
		t.Errorf("should have failed to decrypt, but did not, pt=%v", pt)
	}
}

func TestDecrypt(t *testing.T) {
	z := newTestKeySentinel()
	defer z.Reset()

	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"encrypted password", args{encryptedPlainText}, "plain text", false},
		{"trim", args{"   " + encryptedPlainText + "\n"}, "plain text", false},
		{"invalid base64", args{encryptedPlainText[:len(encryptedPlainText)-1]}, "", true},
		{"non-encrypted password", args{"plain text"}, "plain text", true},
		{"signature, but non-encrypted (error)", args{signature + "plain text"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Decrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	validPacked = bytesjoin([]byte{3, 1, 2, 3}, testNonce(0xcc), []byte{4, 5, 6})
	validCm     = ciphermsg{
		additionalData: []byte{1, 2, 3},
		nonce:          testNonce(0xcc),
		ciphertext:     []byte{4, 5, 6},
	}
)

func Test_pack(t *testing.T) {
	type args struct {
		cm ciphermsg
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"packing ok",
			args{validCm},
			validPacked,
			false,
		},
		{"data too big",
			args{ciphermsg{
				additionalData: make([]byte, maxDataSz+1),
				nonce:          testNonce(0xcc),
				ciphertext:     []byte{4, 5, 6}}},
			nil,
			true,
		},
		{"empty additional data",
			args{ciphermsg{
				additionalData: nil,
				nonce:          testNonce(0xcc),
				ciphertext:     []byte{255, 254, 253},
			}},
			bytesjoin([]byte{0}, testNonce(0xcc), []byte{255, 254, 253}),
			false,
		},
		{"empty nonce",
			args{ciphermsg{
				additionalData: []byte{1, 2, 3},
				nonce:          nil,
				ciphertext:     []byte{255, 254, 253},
			}},
			nil,
			true,
		},
		{"empty ct",
			args{ciphermsg{
				additionalData: []byte{1, 2, 3},
				nonce:          testNonce(0xcc),
				ciphertext:     nil,
			}},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pack(tt.args.cm)
			if (err != nil) != tt.wantErr {
				t.Errorf("pack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("pack() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_unpack(t *testing.T) {
	type args struct {
		packed []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *ciphermsg
		wantErr bool
	}{
		{"ok",
			args{validPacked},
			&validCm,
			false,
		},
		{"empty input", args{}, nil, true},
		{"invalid data length",
			args{bytesjoin([]byte{6, 1, 2, 3}, testNonce(0xcc), []byte{4, 5, 6})},
			nil,
			true,
		},
		{"empty data",
			args{bytesjoin([]byte{0}, testNonce(0xcc), []byte{4, 5, 6})},
			&ciphermsg{
				additionalData: nil,
				nonce:          testNonce(0xcc),
				ciphertext:     []byte{4, 5, 6},
			},
			false,
		},
		{"empty CT",
			args{bytesjoin([]byte{1, 0xdd}, testNonce(0xcc))},
			nil,
			true,
		},
		{"empty everything except data",
			args{[]byte{1, 0xdd}},
			nil,
			true,
		},
		{"nothing to do",
			args{[]byte{0}},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unpack(tt.args.packed)
			if (err != nil) != tt.wantErr {
				t.Errorf("unpack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unpack() = %v, want %v", got, tt.want)
			}
		})
	}
}

// bytejoin aims  to declutter the bytes.Join call in tests.
func bytesjoin(bb ...[]byte) []byte {
	return bytes.Join(bb, []byte{})
}

func Test_armor(t *testing.T) {
	type args struct {
		packed []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{validPacked}, signature + "AwECA8zMzMzMzMzMzMzMzAQFBg=="},
		{"another one", args{}, signature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := armor(tt.args.packed); got != tt.want {
				t.Errorf("armor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_unarmor(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"plain text", args{"some text"}, nil, true},
		{"illegal base64", args{signature + "hey you"}, nil, true},
		{"armored data", args{signature + "AwECA8zMzMzMzMzMzMzMzAQFBg=="}, validPacked, false},
		{"empty text", args{""}, nil, true},
		{"trim space", args{"    " + signature + "AwECA8zMzMzMzMzMzMzMzAQFBg==   "}, validPacked, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unarmor(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("unarmor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unarmor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDecryptError(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"cipher", args{&CipherError{nil}}, true},
		{"corrupt", args{&CorruptError{nil}}, true},
		{"other", args{errors.New("your shotgun is nearby")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDecipherError(tt.args.err); got != tt.want {
				t.Errorf("IsDecryptError() = %v, want %v", got, tt.want)
			}
		})
	}
}
