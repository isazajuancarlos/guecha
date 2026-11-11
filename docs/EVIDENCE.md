<!-- SPDX-License-Identifier: MIT · Copyright (c) Juan Carlos Isaza -->

# Evidence — the measured benches and the discrimination discipline

The claim guecha makes is not "it scans" — plenty of things scan. The claim is
that it **discriminates**: fires on the attack, stays quiet on legitimate
content. That claim is only worth anything if it is measured, so here is how to
reproduce it yourself.

```bash
./build.sh           # compiles and runs both benches
# or individually:
cargo test --release -p olfateador_ofuscacion     # unit, 28 tests
cargo run  --release -p olfateador_ofuscacion --bin probar_olfateador   # E2E
cargo run  --release -p mi_config_tras_leer_fuera --bin probar          # E2E
```

## Results

| Component | Bench | Result |
|-----------|-------|--------|
| `guecha-obfuscation` | unit (`cargo test`) | **28 / 28** |
| `guecha-obfuscation` | E2E `probar_olfateador` | **18 / 18** — warns on 8, stays quiet on 10 |
| `guecha-persistence` | E2E `probar` | **15 / 15** — 6 red, 9 green |

## The discipline (why these numbers mean something)

A bench of only positive cases is a disguised failure: a detector that says "yes"
to everything passes it. So every detector has a **paired** test — a red case
that must fire and a green control that must not — and the green controls are
real legitimate content (emoji sequences, accents, a BOM, CDN images, a cache
buster, config *reads*). A guard that over-fires fails the green half; a blind
guard fails the red half. Only one that discriminates passes both.

Two further rules the benches follow:

- **The red case fails through the real seam.** Each E2E case feeds the detector
  the same way the hook does (the obfuscation bench feeds a tool-result JSON; the
  persistence bench writes a real transcript file and lets `evaluar` read it), so
  a green result cannot come from the test harness bypassing the real path.
- **Mutant-checked.** The detectors were checked against the previous version of
  each rule to confirm the bench goes **red** when the guard is weakened — a test
  that stays green against a broken guard proves nothing.

## Adversarial review

guecha's detectors were put through three rounds of adversarial review. Each
round found real second-order bypasses (an exemption too broad, a normalization
gap, a first-match-only path), each was closed with its own paired test, and one
suggestion was **declined on principle** and documented rather than applied — see
[../SECURITY.md](../SECURITY.md) on why the persistence guard does not embed a
shell lexer or fail closed. Surviving adversarial review *and knowing where to
stop* is the evidence that matters for a security tool.
