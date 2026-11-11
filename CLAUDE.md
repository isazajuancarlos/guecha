# guecha

Prompt-injection defense for AI coding agents, packaged as a Claude Code plugin:
two Rust hooks (`guecha-obfuscation` PostToolUse, `guecha-persistence` PreToolUse)
plus the `origin-rule` skill. Advisory, local, zero-telemetry.

## Build & test

```bash
./build.sh            # compiles release, stages bin/, runs the benches
cargo test --release  # unit tests
```

## Layout

- `crates/` — the two detectors (Rust; one dependency, `serde_json`).
- `hooks/hooks.json` — hook wiring, via `${CLAUDE_PLUGIN_ROOT}/bin/…`.
- `skills/guardia-de-origen/` — the `origin-rule` skill.
- `docs/` — threat model, detectors, evidence, modes, install, hardening, FAQ.

## Conventions

- Every detector ships with a **paired red/green test** (a case that must fire and
  a control that must stay quiet). Don't add a detector without its pair.
- The hooks are **advisory**: they warn via `additionalContext` and always exit 0.
  Never make them block.
- `Cargo.lock` is committed for reproducible builds.

MIT © Juan Carlos Isaza. See `README.md` and `docs/` for details.
