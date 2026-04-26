# AGENTS.md

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
