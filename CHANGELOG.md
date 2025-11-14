# CHANGELOG

## Unreleased

### Added

- **Channel binding support for SCRAM-PLUS variants** (RFC 5929, RFC 9266)
  - Support for `tls-unique` channel binding (RFC 5929)
  - Support for `tls-server-end-point` channel binding (RFC 5929)
  - Support for `tls-exporter` channel binding (RFC 9266) - recommended for TLS 1.3
- New `ChannelBinding` type for configuring channel binding
- New `ChannelBindingType` enumeration with constants for all supported binding types
- `WithChannelBinding()` method on `Client` for SCRAM-PLUS authentication
- `WithChannelBinding()` method on `Server` for validating channel binding
- Comprehensive test suite for channel binding functionality
- `GetStoredCredentialsWithError()` method that returns errors from PBKDF2
  key derivation instead of panicking.
- Support for Go 1.24+ stdlib `crypto/pbkdf2` package, which provides
  FIPS 140-3 compliance when using SHA-256 or SHA-512 hash functions.

### Changed

- Minimum Go version bumped from 1.11 to 1.18.
- Migrated from `github.com/xdg-go/pbkdf2` to stdlib `crypto/pbkdf2` on
  Go 1.24+. Legacy Go versions (<1.24) continue using the external
  library via build tags for backward compatibility.
- Internal error handling improved for PBKDF2 key derivation failures.
- Parser now accepts and validates `p=<cb-type>` gs2-cbind-flag
- Client and server conversations properly handle channel binding data
- README updated with channel binding examples
- Package documentation updated to describe channel binding support

### Deprecated

- `GetStoredCredentials()` is deprecated in favor of
  `GetStoredCredentialsWithError()`. The old method panics on PBKDF2
  errors to maintain backward compatibility but will be removed in a
  future major version.

### Security

- Channel binding prevents man-in-the-middle attacks by cryptographically binding
  SCRAM authentication to the underlying TLS connection
- Constant-time comparison used for all channel binding data validation

### Notes

- FIPS 140-3 compliance is available on Go 1.24+ when using SCRAM-SHA-256
  or SCRAM-SHA-512 with appropriate salt lengths (≥16 bytes). SCRAM-SHA-1
  is not FIPS-approved.

## v1.1.2 - 2022-12-07

- Bump stringprep dependency to v1.0.4 for upstream CVE fix.

## v1.1.1 - 2022-03-03

- Bump stringprep dependency to v1.0.3 for upstream CVE fix.

## v1.1.0 - 2022-01-16

- Add SHA-512 hash generator function for convenience.

## v1.0.2 - 2021-03-28

- Switch PBKDF2 dependency to github.com/xdg-go/pbkdf2 to
  minimize transitive dependencies and support Go 1.9+.

## v1.0.1 - 2021-03-27

- Bump stringprep dependency to v1.0.2 for Go 1.11 support.

## v1.0.0 - 2021-03-27

- First release as a Go module
