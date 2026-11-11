#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) Juan Carlos Isaza
#
# Builds the two guecha hook binaries from source and stages them in bin/ where
# the plugin manifest (hooks/hooks.json) expects them via ${CLAUDE_PLUGIN_ROOT}.
#
# Why build from source instead of trusting a shipped binary: a security tool
# should not ask you to run an opaque binary. You compile it yourself (Rust
# toolchain, one dependency: serde_json) and the bytes are yours. Signed release
# binaries are offered for convenience; verifying a signature or rebuilding here
# are equivalent trust paths — pick either.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> cargo build --release"
cargo build --release

mkdir -p bin
cp target/release/guecha-obfuscation bin/guecha-obfuscation
cp target/release/guecha-persistence bin/guecha-persistence
chmod +x bin/guecha-obfuscation bin/guecha-persistence

echo "==> staged binaries:"
ls -l bin/

echo "==> self-test (the measured benches):"
./target/release/probar_olfateador
./target/release/probar
echo "==> OK. Enable the plugin and the hooks load from bin/."
