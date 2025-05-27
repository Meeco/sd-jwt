# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project (loosely) adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.2.2 - 2025-XX-XX

### Added

- Added checks to make sure there are no duplicate digests

### Changed

- Prevented use of reserved names (`_sd`, `...`) as keys for selectively disclosable claims.

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
