# Changelog

All notable changes to guecha are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); versions follow SemVer.

## [0.1.0] — 2026-11-11

First public release.

### Added
- `guecha-obfuscation` (PostToolUse hook): detects bidirectional controls
  (Trojan Source), zero-width/invisible characters, Unicode Tags smuggling,
  space-flooding, and image-based exfiltration channels in tool output.
- `guecha-persistence` (PreToolUse hook): flags writes to durable agent config
  made in the same turn as an external read, including the shell bypass
  (redirect / `tee` / `sed -i` / `cp`/`mv`/`dd` / variable or `eval` redirect).
- `origin-rule` skill: the judgment-layer discipline for instruction-shaped text
  in tool output.
- Plugin + marketplace manifests, `build.sh`, full `docs/`, and a zero-dependency
  latency bench (`cargo run --release --bin latencia`).

### Notes
- Advisory only: both hooks warn via `additionalContext` and never block.
- 28 unit + 18/18 + 15/15 E2E tests, each detector with a paired red/green case.
  Hardened across three rounds of adversarial review (11 bypasses closed).
- Source-first; `Cargo.lock` committed for reproducible builds.
