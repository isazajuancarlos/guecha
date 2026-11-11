<!-- SPDX-License-Identifier: MIT · Copyright (c) Juan Carlos Isaza -->

# How this repository defends itself

A security tool that cannot protect its own supply chain refutes itself. This
document is the threat model of **the repository**, not of the software it
contains — and it starts by dismantling a framing error.

## The framing error

"How do I protect a public repo from attack?" smuggles in a false goal. The
code here is MIT: anyone may copy it, and that is the *point* — visibility is the
whole reason to publish. You do **not** protect the confidentiality of published
code. You protect three other things:

1. **Integrity / authenticity** — that nobody alters your repository or
   impersonates your releases.
2. **The account** — that it is not taken over.
3. **The protected layer** — which never reaches the public repo at all.

The resolution to "I can't trust the host's goodwill" is not to make the public
surface impenetrable (impossible, and a category error). It is to **architect so
the host holds nothing whose confidentiality matters and nothing whose integrity
you cannot prove independently of the host.** That is the mature posture. The
amateur publishes secrets and hopes; the professional publishes only what is
safe to lose, and signs it.

## The seven controls

### 1. The host is a mirror, not the origin
The authoritative source lives in a **local bare repository** you control. The
public host is a push mirror for visibility. If the host tampers with or loses
your repo, your truth is untouched and you re-push. This also gives you
detection (control 7).

### 2. Sign commits and tags
Sign every commit and every release tag with a key the host **never holds**
(hardware-backed if possible). Consumers verify authenticity against your public
key regardless of the host. Enable "require signed commits" and vigilant mode so
unsigned commits show as unverified.

### 3. Sign the release artifact
If you ship a prebuilt binary, sign it (minisign/cosign/GPG) and publish
checksums. Pair it with reproducible build instructions so anyone can rebuild
from source and compare bytes. Verifying a signature and rebuilding are then
equivalent trust paths.

### 4. Ship source, not just a binary
A security tool must not require running an opaque binary. Ship the source and a
`build.sh`; let the security-conscious compile it themselves. `Cargo.lock` is
committed so the build is reproducible.

### 5. Disable CI/Actions on the repo
No CI means no automation token (`id-token`), no stored secret, and no runner to
hijack — it removes the single largest automated attack surface on a modern
code host. If you need checks, run them locally with the exact command; a green
local build is the only green you depend on.

### 6. Branch protection
On the published branch: require signed commits, require pull-request review,
forbid force-push and deletion. No auto-merge. With Actions off, a malicious PR
cannot execute code on your infrastructure — it can only propose text you
review by hand before anything lands.

### 7. Hardware 2FA, minimal tokens, and tamper detection
Anchor the account with a hardware security key. Scope every token to the
minimum; prefer fine-grained, short-lived tokens over broad classic ones.
Because you mirror from a local origin (control 1), a periodic
`git fetch <host> && git diff <host>/main main` against your local truth detects
any unauthorized change the host-side security log might miss.

## What these controls do NOT prevent — stated honestly

- **Copying.** Anyone may clone and reuse MIT code. That is the license working
  as intended, not a breach.
- **Host downtime.** The host can go offline. Your local origin means you lose
  nothing but a mirror.

Naming these is part of the posture: a control that claims to stop the
unstoppable trains you to ignore the ones that work.

## The division that makes it coherent

| Lives on the public host | Never leaves your machine |
|---|---|
| The MIT core (disposable by design) | Anything whose value is secrecy: cryptographic alpha, client tooling, proprietary methods |
| Signed tags & signed release binaries | The signing private key |
| Reproducible-build instructions | The authoritative bare repository |

You publish what is safe to lose and prove everything with a key the host never
sees. That is why you do not have to trust the host's goodwill — you designed the
trust out.
