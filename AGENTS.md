# AGENTS.md

- **Threat model: in-process, not adversarial.** haunt runs as a DLL
  inside the user's target — we share the host's address space and
  every lock the host takes. There is no network attacker to defend
  against; the user owns the box. Loopback-only HTTP with opt-in auth
  is all the security work we do, and we will not invest more there.

  What we *do* care about, with no compromise: **correctness, zero
  bugs, no surprises**. A single panic kills the host. A silent
  default — "user typoed `--halft-if`, treat it like the BP had no
  gate" — produces a target-process bug that surfaces hours later as
  "haunt did something different than I asked." Strict validation,
  panic-free hot paths, no `unwrap` / `expect`, no `unwrap_or` on
  user-supplied input, no silently-ignored flags or query params, no
  silent clamping — all non-negotiable. Not because of attackers,
  because we live in someone else's process and any bug is their bug.
- Workspace cross-compiles to `x86_64-pc-windows-gnu` by default; for
  32-bit, `--target i686-pc-windows-gnu`. `cargo run` won't execute on
  non-Windows hosts.
- `haunt-windows` is a `cdylib` with `panic = "abort"`. Any panic kills
  the host. No `unwrap` / `expect` in production paths.
- `CONTEXT` register field names differ between x64 and x86. Go through
  `breakpoint::arch` instead of touching `ctx.Rip`/`ctx.Eip` directly.
- Cross-platform logic lives in `haunt-core`; platform calls live in
  `haunt-windows`.
- Keep `README.md` in sync with code changes.
- Keep the `haunt` CLI help text (`USAGE` in `crates/cli/src/main.rs`)
  in sync with command/flag changes.
- Keep all documentation brief and factual. No wordiness, no fluff.
- Always apply the best possible fix regardless of whether the syntax,
  protocol, or behavior is backwards compatible. No deprecation shims,
  no compat aliases, no "preserve old form for callers." Update the
  README, USAGE, and any CHANGELOG entry to match.
- Prefer strict validation and clear rejection over silent acceptance.
  Bad inputs to API calls — unparseable numbers, unknown enum values,
  unsupported flag combinations (e.g. `--access` with `kind=sw`) — must
  return a `400` (HTTP) or non-zero exit (CLI) with a message that
  names the offending parameter. No silent defaults, no `unwrap_or`
  fallbacks on user-supplied values, no quietly-ignored flags. The
  user must learn from the error what to change; guessing what they
  meant produces target-process bugs that surface hours later.
