# AGENTS.md

- Workspace cross-compiles to `x86_64-pc-windows-gnu` by default
  (`.cargo/config.toml`). `cargo run` won't execute on non-Windows hosts.
- `haunt-windows` is a `cdylib` loaded into arbitrary processes and
  `panic = "abort"` is set — any panic kills the host. No `unwrap` /
  `expect` in production paths.
- Prefer putting cross-platform logic in `haunt-core` (keeps the
  planned Linux port simpler).
