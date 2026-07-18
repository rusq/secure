# Secure v2

`github.com/rusq/secure/v2` provides versioned authenticated encryption for
small values, JSON fields, and streams. Version 2 uses AES-256-GCM, immutable
encryption contexts, bounded parsing, and an Argon2id password mode.

The package protects ciphertext integrity and confidentiality. It does not
protect plaintext already present in process memory, weak passwords, or keys
stored alongside encrypted data.

## Installation

```sh
go get github.com/rusq/secure/v2@v2.0.0
```

Version 2 requires Go 1.25 or newer.

## Key-based encryption

```go
key := make([]byte, 32) // load this from a secret manager
c, err := secure.NewCipher(key)
if err != nil {
	log.Fatal(err)
}

encrypted, err := c.EncryptString("database password")
plaintext, err := c.DecryptString(encrypted)
```

Use `Seal` and `Open` when associated data should bind ciphertext to a field,
tenant, or record. The same associated data must be supplied during decryption.

## Password-based encryption

```go
p, err := secure.NewPasswordCipher([]byte(passphrase))
encrypted, err := p.EncryptString("secret")
plaintext, err := p.DecryptString(encrypted)
```

Each `SEC2.` envelope gets a random salt and records its bounded Argon2id
parameters. The default cost is 64 MiB, three passes, and four threads.

## Authenticated streams

```go
w, err := c.NewEncryptWriter(dst)
if err != nil { /* handle */ }
if _, err := io.Copy(w, src); err != nil { /* handle */ }
if err := w.Close(); err != nil { /* required: writes final record */ }

r, err := c.NewDecryptReader(encryptedSource)
_, err = io.Copy(plaintextDestination, r)
```

Stream readers authenticate each 64 KiB record and reject modified, reordered,
or truncated streams. Plaintext already returned before a later error cannot be
retracted, so callers must discard partial output when decryption fails.

## Encrypted JSON values

Construct `EncryptedString` or `EncryptedInt` with a cipher before marshaling or
unmarshaling. Plaintext JSON is rejected unless
`WithPlaintextJSONMigration()` is explicitly supplied. A migrated value is
encrypted on its next marshal.

## Migrating from v1

V2 does not expose v1 global configuration or AES-CFB stream APIs. Re-encrypt
stored values one at a time:

```go
plaintext, err := secure.OpenLegacyWithPassphrase(oldValue, oldPassphrase,
	secure.WithLegacySalt(oldSalt))
newValue, err := p.Seal(plaintext, nil)
```

`OpenLegacy` accepts an already-derived 32-byte key. Legacy options support
custom v1 salts, PBKDF2 iteration counts, armor prefixes, and base64 encodings.
Only legacy decryption is available; v2 never creates `SEC.` ciphertext.

Never commit production keys, passphrases, or salts. Treat changes to envelope
or stream formats as compatibility-sensitive security changes.
