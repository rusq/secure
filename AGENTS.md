# Repository Guidelines

## Project Structure & Module Organization

This single Go module (`github.com/rusq/secure/v2`) implements the `secure` package. Production code lives at the root: `secure.go` contains versioned AES-GCM envelopes, `stream.go` handles authenticated streams, `legacy.go` supports read-only v1 migration, and `string.go` and `int.go` provide encrypted JSON values. Tests are colocated in `*_test.go` files, and `README.md` documents the API.

## Build, Test, and Development Commands

- `make test` runs the full suite with the race detector, two executions, and coverage.
- `go test ./...` provides a faster local test pass.
- `go test ./... -race` checks for concurrency issues.
- `go vet ./...` performs standard Go static analysis.
- `go build ./...` confirms all packages compile.
- `gofmt -w *.go` formats Go source and tests before review.
- `make check` runs formatting, vet, race-enabled tests, and the build.

Use the Go version declared in `go.mod` (currently Go 1.25). Run `go mod tidy` only when dependencies change, and include resulting `go.mod` and `go.sum` updates together.

## Coding Style & Naming Conventions

Follow standard Go conventions and let `gofmt` determine indentation and spacing. Use short, lowercase filenames and idiomatic mixed-cap identifiers: exported API names use `CamelCase`; internal helpers use `camelCase`. Add Go doc comments to exported declarations. Keep cryptographic packing constants and related logic close together, and return or wrap errors rather than silently accepting malformed ciphertext.

## Testing Guidelines

Tests use Go's standard `testing` package. Name top-level tests `TestXxx`; prefer table-driven cases with descriptive `t.Run` names for validation branches. Add regression tests beside the affected implementation. Because ciphertext uses random nonces, assert successful round trips and error behavior instead of newly generated ciphertext bytes. Run `make test` before submitting changes; maintain or improve coverage for changed paths.

## Commit & Pull Request Guidelines

Recent commits use short, imperative, lowercase subjects such as `add stream encryption/decryption`. Keep commits focused and explain compatibility or security implications in the body. Pull requests should summarize behavior changes, list verification commands, link relevant issues, and call out API, ciphertext-format, dependency, or salt changes. Screenshots are generally unnecessary for this library.

## Security & Configuration Tips

Never commit real passphrases, keys, salts, or production ciphertext. Load 32-byte keys from managed secret storage; password envelopes generate their own salts. Treat changes to derivation parameters, nonce handling, authenticated headers, or serialized layouts as security-sensitive and compatibility-affecting.
