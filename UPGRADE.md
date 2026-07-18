# Upgrading from v0.0.4 to v2

Version 2 is a security-focused, source-breaking release. It replaces package-wide state and unauthenticated AES-CFB streams with immutable cipher instances, versioned `SEC2.` envelopes, and authenticated streaming.

## Update the Dependency

After `v2.0.0` is published:

```sh
go get github.com/rusq/secure/v2@v2.0.0
go mod tidy
```

Update imports to use the semantic import suffix:

```go
import secure "github.com/rusq/secure/v2"
```

## Replace Global Configuration

Create and retain an immutable encryption context instead of calling package setters:

```go
// For a 32-byte key loaded from managed secret storage.
cipher, err := secure.NewCipher(key)

// Or for password-based encryption.
cipher, err := secure.NewPasswordCipher(passphrase)
```

Pass this instance into the components that require encryption.

| v0.0.4 | v2 |
| --- | --- |
| `SetGlobalKey(key)` | `NewCipher(key)` |
| `SetPassphrase(pass)` | `NewPasswordCipher(pass)` |
| `Encrypt(text)` | `cipher.EncryptString(text)` |
| `Decrypt(text)` | `cipher.DecryptString(text)` |
| `SetSalt`, `SetEncoding`, `SetSignature` | Removed for new envelopes |
| `NewWriter`, `NewReader` | Instance stream methods |

Use `Seal` and `Open` when encrypting bytes or binding ciphertext to associated data:

```go
encrypted, err := cipher.Seal(plaintext, []byte("tenant:123/field:token"))
plaintext, err = cipher.Open(encrypted, []byte("tenant:123/field:token"))
```

The associated data must match during decryption but is not stored in the envelope.

## Migrate Stored Ciphertext

V2 writes only `SEC2.` envelopes. It can read historical `SEC.` values through explicit migration helpers.

For data encrypted with the v1 default salt:

```go
plaintext, err := secure.OpenLegacyWithPassphrase(oldValue, oldPassphrase)
if err != nil {
	return err
}

newValue, err := cipher.Seal(plaintext, nil)
```

Supply historical configuration when v1 used custom settings:

```go
plaintext, err := secure.OpenLegacyWithPassphrase(
	oldValue,
	oldPassphrase,
	secure.WithLegacySalt(oldSalt),
	secure.WithLegacyIterations(oldIterations),
	secure.WithLegacyPrefix(oldPrefix),
	secure.WithLegacyEncoding(oldEncoding),
)
```

Use `OpenLegacy(oldValue, oldKey)` when the historical 32-byte derived key is already available.

During a staged rollout:

1. Read `SEC2.` values with the normal v2 cipher.
2. Read `SEC.` values only with the legacy migration helpers.
3. Re-encrypt successfully decoded values as `SEC2.` and persist them.
4. Remove legacy reading after inventories confirm no `SEC.` values remain.

Never silently treat an unrecognized encrypted value as plaintext.

## Update JSON Fields

The old `String` and `Int` aliases are replaced by instance-bound values. Configure each field before unmarshalling:

```go
type Config struct {
	Secret secure.EncryptedString `json:"secret"`
}

func decodeConfig(data []byte, cipher secure.Codec) (Config, error) {
	secret, err := secure.NewEncryptedString(cipher, "")
	if err != nil {
		return Config{}, err
	}

	cfg := Config{Secret: secret}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}
```

Access the plaintext through `Value` and update it through `Set`:

```go
current := cfg.Secret.Value()
cfg.Secret.Set("replacement")
```

`NewEncryptedInt` follows the same pattern. Plaintext JSON is rejected by default. If existing configuration files contain plaintext during migration, explicitly opt in:

```go
secret, err := secure.NewEncryptedString(
	cipher,
	"",
	secure.WithPlaintextJSONMigration(),
)
```

The next JSON marshal encrypts the migrated value.

## Replace Stream Encryption

Encrypt streams through the cipher instance:

```go
writer, err := cipher.NewEncryptWriter(destination)
if err != nil {
	return err
}
if _, err := io.Copy(writer, source); err != nil {
	return err
}
if err := writer.Close(); err != nil {
	return err
}
```

`Close` is mandatory because it writes the authenticated final record. Decrypt with:

```go
reader, err := cipher.NewDecryptReader(encryptedSource)
if err != nil {
	return err
}
_, err = io.Copy(destination, reader)
```

Discard partial output if stream decryption returns an error.

V2 cannot directly read v1 AES-CFB streams. Migrate them with a temporary tool that imports v0.0.4 under an alias, decrypts using the original key and IV, and writes the plaintext through a v2 authenticated writer. Do not retain CFB support in the production path.

## Validate the Rollout

Before deployment, verify that:

- Representative default- and custom-salt `SEC.` values migrate successfully.
- Wrong keys, passwords, or associated data return an authentication error.
- Plaintext JSON is accepted only where migration mode was deliberately enabled.
- Every encrypting stream writer is closed and truncated streams are rejected.
- Persisted data is progressively rewritten with the `SEC2.` prefix.
- Tests run with `go test ./... -race`.
