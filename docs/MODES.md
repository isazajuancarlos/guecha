<!-- SPDX-License-Identifier: MIT · Copyright (c) Juan Carlos Isaza -->

# Modes — advisory today, enforce on the roadmap

## Advisory (the only mode today, and the default forever)

guecha **warns, it does not block.** Both hooks emit their finding via
`additionalContext` — the channel that reaches the model's context — and always
exit 0. Nothing is ever halted.

This is a deliberate design choice, not a missing feature:

- **The model has the full context; the hook does not.** A blocking guard that
  fires on a false positive halts legitimate work, and the hook cannot tell a
  real attack from a lookalike as well as the model can with the whole
  conversation in view.
- **Guards that cry wolf get routed around.** An advisory that is right most of
  the time keeps being read; a blocker that is wrong even occasionally gets
  disabled. Staying advisory keeps the signal trusted.
- **The warning is actionable.** It names the carrier or the fingerprint and
  restates the origin rule, so the model can quote the suspicious content, name
  its source, and ask — which is the correct response to a suspected injection.

## Enforce (roadmap / pro)

A blocking mode — where the persistence guard can `deny` a config write, or the
obfuscation guard can hold a tool result — is viable but is a different risk
profile, and belongs behind explicit opt-in because a false block is disruptive.
The design constraint: enforce mode must be **per-rule and opt-in**, must key on
only the highest-confidence fingerprints (e.g. a config write from a
demonstrably external, non-user source), and must fail *open* on any ambiguity,
so it never becomes the cry-wolf blocker that advisory mode exists to avoid.

This is where an organization-facing tier makes sense: enforce mode, policy packs
(which paths count as protected config for your setup), CI reporting, and
multi-repo rollup — none of which a single developer running the free advisory
hooks needs.

## Configuration

Today the hooks need no configuration — they ship with sensible matchers
(`hooks/hooks.json`) and protected-path defaults. The protected config paths and
the external-source definitions are compiled in; making them configurable
(for non-default `~/.claude` layouts, or additional sensitive files) is a
roadmap item, gated on a real request so the default stays zero-config.
