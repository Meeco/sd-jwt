# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project (loosely) adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.3.0 - UNRELEASED

- fix: reject a Key Binding JWT whose typ header is not kb+jwt
- fix: a Key Binding JWT that is present must always be verified; previously it was ignored unless `kb.verifier` was supplied
- fix: validate the Key Binding JWT's sd_hash against the presented SD-JWT
- fix: reject an `_sd_alg` that is not one of sha-256, sha-384, sha-512, sha3-256, sha3-384, sha3-512 instead of passing it to `getHasher`
- fix: enforce `exp` and `nbf`; pass `{ time: { skip: true } }` to leave the validity period to the verifier callback, or `{ time: { skewSeconds } }` to allow for clock drift
- fix: check the Key Binding JWT's `iat`, by default within 10 minutes of now; pass `{ kb: { iat: { skewSeconds } } }` for a different window, or `{ kb: { iat: false } }` to accept a proof of possession of any age

## 1.2.4 - 2026-08-24

### Security

- Reject SD-JWT presentations containing a Disclosure that isn't referenced by any digest in the payload, per RFC 9901 §7.1 step 5. Prevents an attacker from smuggling in an extra or substituted Disclosure alongside a legitimately signed one.
- Reject disclosures and JWT parts containing invalid UTF-8 instead of silently lossy-decoding them.
- Reject SD-JWT presentations with a duplicate disclosure using a distinct error message

### Changed

- Updated devDependencies (esbuild, jest, @types/jest, eslint, @eslint/js, eslint-config-prettier, globals) and fixed the resulting deprecated Jest matcher usages.
- Typescript upgraded from 5.6.2 to 6.0.3

## 1.2.3 - 2026-06-22

### Fixed

- Re-exported SD-JWT constants from the package index.

## 1.2.2 - 2025-05-28

### Added

- Added checks to make sure there are no duplicate digests
- Increased SD-JWT unpack strictness: now rejects on duplicate properties, invalid keys from disclosures, reserved key and invalid array digests.

### Changed

- Prevented use of reserved names (`_sd`, `...`) as keys for selectively disclosable claims.
- Refactor some tests with helpers to improved readability

## 1.2.1 - 2024-10-04

### Changed

- Updated `JWK` type and `kty` property made required.

## 1.2.0 - 2024-09-27

### Added

- Added `_sd_decoy` option to specify number of decoy element to add.

### Deprecated

- Deprecated `_decoyCount` option.

### Fixed

- Fixed `DisclosureFrame` type definition not to use `unknown`.

## 1.1.0 - 2024-08-14

### Added

- Added parsed token header data to the result of the `decodeSDJWT` function

## 1.0.2 - 2024-03-13

### Fixed

- imports for esm build

### 1.0.1 - 2024-03-13

### Fixed

- jsonpath exports

## 1.0.0 - 2024-03-07

### Added

- listing and selecting disclosures with explicit Jsonpath dot-notation

## 0.0.4 - 2024-02-01

- Bug fix: base64decode for browser runtime

## 0.0.3 - 2023-10-17

### Changed

- added feature to add decoy sd digests

## 0.0.2 - 2023-10-03

### Changed

- added createSDMap

### Fixed

- base64 encode/decode support for browser and node runtime

## 0.0.1 - 2023-09-26

Initial version

### Changed

- add E2E test
- removed kb jwt payload checks
- added error types
- removed `jose` dependency
- added simple demo scripts
- add `.js` file extensions to all imports for ESM compatibility
