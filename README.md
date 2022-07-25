# Secure (almost)

Secure provides a convenient String and Int types that are encrypted with the
AES-256 with GCM upon Marshalling/Unmarshalling to JSON.

It uses the standard Go runtime encryption.

Do not use the provided "salt" for anything other than testing - it may change
from version to version to encourage to use your own salt.

It is strongly encouraged to set your own salt with SetSalt() before using the
package.
