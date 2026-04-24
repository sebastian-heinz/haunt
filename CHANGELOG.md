# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1]

### Added
- Symbol-by-name breakpoints: `bp set kernel32.dll!CreateFileW` resolves
  server-side against module export tables.
- `GET /symbols/resolve?name=module!symbol` and `haunt resolve` CLI.
- Stack walking: `GET /halts/<hit_id>/stack?depth=N` walks the rbp chain
  and resolves each frame to `module+0xoffset`. `haunt stack <hit_id>`
  CLI.
- `binaries` workflow: on `v*` tags, cross-compiles `haunt.dll`,
  `haunt-inject.exe`, `haunt.exe` for Windows and attaches them to the
  GitHub release with SHA256SUMS.

### Changed
- `parse_query` now percent-decodes values, so symbols and parameters
  containing non-ASCII-safe characters (mangled C++/Rust names, `+`,
  `=`, etc.) round-trip correctly.
- `/modules/<name>/exports` percent-decodes the `<name>` path segment.
- `/bp/set` rejects passing both `addr` and `name` with `400`.

### Fixed
- `/bp/set` and `/symbols/resolve` return `400` for malformed names
  (missing `!`) instead of `404`; genuine not-found still returns `404`.
- CLI `stack --depth N` builds well-formed URLs even when `--depth` is
  specified more than once (last value wins).

### Docs
- README: `module!symbol` in examples, new `/stack` and
  `/symbols/resolve` endpoints, accurate description of the hardcoded
  loopback bind and how to reach the agent remotely via SSH tunnel.
- Added `AGENTS.md` with workspace target, cdylib safety invariants,
  and guidance to keep cross-platform logic in `haunt-core`.

## [0.1.0]

Initial release. Memory read/write, software/hardware/page breakpoints,
halt with register snapshot, resume/step/run-to-return, module and
export enumeration. x86_64 Windows only.
