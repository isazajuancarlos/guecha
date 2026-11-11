<!-- SPDX-License-Identifier: MIT · Copyright (c) Juan Carlos Isaza -->

# Detectors — what each one flags, and how it discriminates

Every detector is tuned to **discriminate**: it must fire on the attack *and*
stay quiet on legitimate content. Each ships with a paired red/green test (a case
that must fire and a control that must not). See [EVIDENCE.md](EVIDENCE.md).

## `guecha-obfuscation` (PostToolUse)

Runs after `Read`, `WebFetch`, `WebSearch`, `Bash`, `Grep`, `Task` and MCP tools.
Decodes the JSON hook payload (including `\uXXXX` escapes, so an invisible
character does not slip through as a false negative) and scans the extracted text.

### `bidi` — bidirectional controls
Flags any of the override/isolate controls (LRE, RLE, PDF, LRO, RLO, LRI, RLI,
FSI, PDI). Any occurrence is suspicious in code, READMEs and shell output.

### `ancho-cero` — invisible characters
Flags invisible/zero-width characters (ZWSP, ZWNJ, ZWJ, word joiner, BOM, soft
hyphen, the directional marks LRM/RLM/ALM, the mathematical invisibles) when they
either **touch a letter/digit** (embedded in a word) **or appear in a run of two
or more** (padding). 
- *Quiet on:* a single ZWJ between emoji (an emoji sequence), a lone BOM at file
  start, Spanish accents, a single stray invisible between spaces.

### `tag-smuggling` — Unicode Tags block
Flags characters in U+E0000–E007F (ASCII smuggling). The only legitimate use is
emoji subdivision flags, so the exemption is an **allowlist of the three real RGI
flags** (England `gbeng`, Scotland `gbsct`, Wales `gbwls`) — a run with any other
code, even in valid flag format, is still flagged.

### `relleno-horizontal` / `relleno-vertical` — space flooding
Flags a run of ≥300 spaces/tabs on one line, or ≥40 consecutive blank lines —
pushing text out of view. Skipped for generated files (`.min.js`, lockfiles, …)
that legitimately contain such runs.

### `exfil-imagen` — image exfiltration channel
Flags an image (`![](URL)` or `<img src=URL>`) whose URL is **external**, has a
**query/fragment**, and whose tail **looks like data** (a long base64/hex run, or
heavy `%`-encoding). All three must hold, so a normal documentation image stays
quiet.
- *External* is normalized WHATWG-style: control characters stripped, `\`→`/`,
  `http:/host` (one slash) and `https:\\host` and protocol-relative `//host` all
  count as external; `<img>` is matched case-insensitively; a relative URL is not
  external.
- *Quiet on:* a relative image, an external CDN image with no payload, a short
  cache-buster (`?v=2`), a localhost URL.

### `entrada-truncada` — oversized input
If a tool result exceeds the scan budget, guecha scans the **head and the tail**
(so padding at the front cannot hide a payload at the end) and emits this notice
so the oversized input is itself reported rather than passing silently.

## `guecha-persistence` (PreToolUse)

Runs before `Write`, `Edit`, `MultiEdit`, `NotebookEdit` and `Bash`. Fires only
when **both** hold:
1. The operation **writes durable config** — `~/.claude/CLAUDE.md`,
   `settings.json`, `settings.local.json`, or anything under `~/.claude/hooks/`.
   Detected from the tool's `file_path`, or — for `Bash` — from a redirect
   (`>`/`>>`), `tee`, `sed -i`, `truncate`, a `cp`/`mv`/`install`/`dd` to the
   path, or a variable/`eval` redirect that names it.
2. In the **same turn**, the agent read from an **external source** (web, skill,
   MCP, subagent, remote fetch), established against the unforgeable human-turn
   boundary in the transcript.

- *Quiet on:* reading config (`cat ~/.claude/CLAUDE.md`), writing to a
  non-config path, or a config write with no external read in the turn.

The Bash detection is a best-effort secondary net with a documented limit (it
does not fully parse shell); the real guard against this class is the
`origin-rule` skill. See [../SECURITY.md](../SECURITY.md).

## `origin-rule` (skill)

Not a detector — the judgment layer. Loaded when instruction-shaped text appears
in a tool result: quote it, name its source, ask the user; never act-then-report.
