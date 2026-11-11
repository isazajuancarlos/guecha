<!-- SPDX-License-Identifier: MIT · Copyright (c) Juan Carlos Isaza -->

# FAQ

**Does guecha send anything anywhere?**
No. No network, no telemetry, no account. Both hooks read the tool payload on
stdin and write a warning to stdout. That's all.

**Will it block my work or slow it down?**
It never blocks — it only warns (see [MODES.md](MODES.md)). The checks are
local string scans over the tool output; the cost is sub-millisecond in the
common case, with a bounded scan budget for pathological inputs.

**Why advisory and not blocking?**
Because the model has the full context and the hook does not, and because a guard
that cries wolf gets disabled. guecha surfaces the signal; the model decides.
Enforce mode is on the roadmap, opt-in, per-rule. See [MODES.md](MODES.md).

**Does it detect "ignore previous instructions" and jailbreak phrases?**
Deliberately **no**. A catalog of injection phrases fires on legitimate content —
including a security team's own corpus — and trains you to ignore it. guecha
flags the *obfuscation carrier* (what a human can't see) and the *persistence
fingerprint* (writing config after reading outside); judging a plainly-visible
instruction is the `origin-rule` skill's job, which is the model's judgment, not
a regex.

**Will it false-positive on my emoji / RTL text / minified JS?**
It's tuned not to: single ZWJ in emoji sequences, the three real subdivision flag
emojis, a BOM at file start, accents, and generated files are all quiet. The
green half of every paired test is exactly these cases
(see [EVIDENCE.md](EVIDENCE.md)). If you find a false positive, that's a bug worth
reporting ([SECURITY.md](../SECURITY.md)).

**Does it work with Cursor / other MCP clients?**
The hooks are Claude Code hooks. The same detection logic is packaging-agnostic;
an MCP-server packaging (usable by any MCP client) is a natural next step.

**Can it catch every shell trick to write my config?**
No, and it doesn't claim to — the Bash detection is a best-effort secondary net
with a documented limit. The real guard against config poisoning is the origin
rule. See [../SECURITY.md](../SECURITY.md).

**What's the license? Can I use it commercially?**
MIT. Use it, copy it, ship it. See [../LICENSE](../LICENSE).

**Who made this?**
Juan Carlos Isaza. guecha is the open core of a small suite of defensive tooling.
