<!-- SPDX-License-Identifier: MIT · Copyright (c) Juan Carlos Isaza -->

# Security Policy

guecha is a security tool, so it holds itself to the standard it enforces.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private
vulnerability reporting (the **Security** tab → *Report a vulnerability*), which
opens a private advisory visible only to the maintainer.

If private reporting is unavailable, email the maintainer (see the repository
owner's profile) with `[guecha-security]` in the subject.

Please include: the affected version/commit, a minimal reproduction, and the
impact you observed. A proof-of-concept is welcome but never required.

## What to expect

- Acknowledgement within a few days.
- Coordinated disclosure: we agree on a timeline and credit you (unless you
  prefer to stay anonymous) once a fix ships.

## Scope

In scope: detection bypasses (obfuscation that guecha should flag and doesn't),
fail-open conditions (input that makes a hook time out or crash so content
passes unscanned), false-positive floods, and any way the hooks themselves could
be turned into an exfiltration or code-execution vector.

Out of scope: that MIT-licensed code can be copied (by design); that the tool is
advisory and does not block by default (documented in `docs/MODES.md`).

**Known limitation, by design — the persistence guard's Bash detection is a
best-effort SECONDARY net.** Its primary mechanism is exact (the `file_path` of
Write/Edit/NotebookEdit); the Bash-command inspection catches the common shell
bypasses (`>`/`>>`/`tee`/`sed -i`/`cp`/`mv`/variable or `eval` redirects to a
protected config path) but does **not** fully parse shell. A determined,
obfuscated one-liner (`base64 | sh`, `$IFS`, computed paths) can still reach
config. We deliberately do **not** embed a shell lexer or fail closed on every
command that merely names a config path: an advisory that fires on a plain
`cat ~/.claude/CLAUDE.md` read would train users to ignore it, and chasing
shell-parse completeness in a secondary heuristic is a losing arms race. The real
guard against this class is the **origin rule** (the `origin-rule` skill): an
instruction to write config that did not come from the user is an injection,
whatever shell trick carries it.

## Verifying what you install

guecha is **source-first**: compile it yourself (`./build.sh`), with
`Cargo.lock` committed for a reproducible build. Release binaries, when offered,
are signed with the maintainer's key (ed25519 / minisign) and published with
SHA-256 checksums — verifying the signature and rebuilding from source are
equivalent trust paths. See `docs/HARDENING.md`.
