<!-- SPDX-License-Identifier: MIT · Copyright (c) Juan Carlos Isaza -->

# Install

guecha is **source-first**: you compile two small Rust binaries yourself (one
dependency, `serde_json`), so you never run an opaque binary from a security
tool. `Cargo.lock` is committed for a reproducible build.

## Requirements

- A Rust toolchain (`rustc` + `cargo`), stable. Install via [rustup](https://rustup.rs).
- Linux or macOS. Windows support needs a per-platform wrapper (roadmap — see below).

## Build

```bash
git clone <this-repo> guecha
cd guecha
./build.sh
```

`build.sh` compiles in release mode, stages the two binaries in `bin/`
(`guecha-obfuscation`, `guecha-persistence`), and runs the benches so you can see
them pass on your machine.

## Enable as a Claude Code plugin

The plugin manifest (`.claude-plugin/plugin.json`) and hook declarations
(`hooks/hooks.json`) reference the binaries via `${CLAUDE_PLUGIN_ROOT}/bin/…`, so
once the plugin is installed and built, the hooks resolve automatically.

- **From a local checkout** (source-first, recommended): add this repo as a local
  marketplace and install:
  ```
  /plugin marketplace add /path/to/guecha
  /plugin install guecha@guecha
  ```
  (`claude plugin validate .` checks the manifest first.)

- **From a hosted marketplace**: add the marketplace that lists guecha, then
  `/plugin install guecha@<marketplace>`. Because guecha is distributed
  source-first, the plugin still expects you to have run `./build.sh` so `bin/`
  is populated.

Reload with `/reload-plugins` (or restart the session). The obfuscation hook
runs after content-reading tools; the persistence hook runs before writes and
`Bash`.

## Verify what you installed

```bash
# rebuild from source and confirm the benches pass
./build.sh
```

If release binaries are offered, verify the signature (ed25519 / minisign) and
the published SHA-256 — rebuilding from source and verifying a signed binary are
equivalent trust paths. See [HARDENING.md](HARDENING.md).

## Platforms (roadmap)

There is no build step at plugin-install time, so the binaries must exist before
the hooks fire — `./build.sh` handles that on Linux/macOS. Windows and a
prebuilt, signed release per platform (with a `uname`-based wrapper to pick the
right binary) are a roadmap item; today the source build is the supported path.

## Uninstall

Remove the plugin (`/plugin uninstall guecha@<marketplace>`) and delete the
checkout. guecha stores no state, writes nothing outside the build, and makes no
network calls.
