# Secure (almost)

Secure provides convenient String and Int types that are encrypted with
AES-256-GCM when marshaled to JSON and decrypted when unmarshaled.

It uses the standard Go runtime encryption.

The bundled salt is fixed for ciphertext compatibility and is not secret. Use a
stable, application-specific salt configured with SetSalt before deriving keys.
Changing the salt makes existing passphrase-encrypted values unreadable.

Global keys, salts, signatures, encodings, and DeriveIter must be configured
before encryption starts and must not be changed concurrently with use.

The legacy stream helpers use AES-CFB and provide confidentiality only: they do
not detect modified, reordered, or truncated ciphertext. Do not use them for new
applications. The authenticated stream API is available in
`github.com/rusq/secure/v2`.
