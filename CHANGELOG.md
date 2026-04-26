# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-04-26

### Added
- **Memory search now requires an explicit scope**. `/memory/search` and
  `haunt search` reject requests with no `module`, `start`/`end`, or
  `all=true` — a whole-address-space scan on a multi-GB target can pin
  a worker for minutes (one `ReadProcessMemory` chunk at a time, no
  progress, no cancel), and "no scope = scan everything" was a UX
  footgun. Users who genuinely want a whole-AS sweep opt in via
  `all=true` (HTTP) / `--all` (CLI). Existing scoped searches are
  unchanged.
- **Forwarded exports now resolve**: `bp set kernel32.dll!ExitProcess`
  used to 404 because the manual export-table walk skipped forwarded
  entries. Symbol lookup now goes through `GetProcAddress` (added as a
  new `Process::resolve_symbol` trait method, default-impl'd in terms
  of `module_exports` for non-overriding platforms), which follows
  forwarders and API-set redirection the way every other Windows
  debugger does. `bp set` echoes the resolved address back as
  `id=N addr=0x...` so users can see when a lookup crossed a forwarder.
  `bp list` carries `requested=<original-name>` for breakpoints set by
  name. `/modules/<name>/exports` now lists forwarded entries as
  `name=Foo forward=other.dll.RealName` instead of dropping them.
- **Two-pool in-flight cap**: total worker threads capped at
  `MAX_IN_FLIGHT = 80`; long-poll endpoints (`/halts/wait`, `/events`)
  share a sub-cap of `MAX_LONG_POLL = 64`. The 16-slot gap is reserved
  for short requests, so a flood of stuck `/halts/wait` calls can
  never lock the user out of their own `bp clear`/`resume`/`regs` —
  the failure mode that motivated the sub-pool. Slot acquisition is a
  relaxed CAS loop on per-pool atomics; release is RAII via a
  `SlotGuard` that drops when the worker thread exits. Over either
  cap the accept thread responds `503 too busy` inline (no thread
  spawn).
- `GET /info` returns `version=...\narch=x86_64|x86\npid=...\nuptime_ms=...`.
  Lets clients pick the right calling convention (the same protocol talks
  to both bitnesses) and surfaces basic agent metadata in one shot. CLI
  gains a `haunt info` command and uses `arch` to pick a default
  `--conv` (`win64` for x64, `cdecl` for x86); `args --conv thiscall`
  against an x64 agent now errors instead of silently returning garbage.
- `Process` trait gains `pid()` and `current_os_tid()`. Required by
  `/info` and by the agent-thread tracking below; both are trivial
  Win32 calls on the current Windows impl.
- `thread_role::agent_tids()` returns a snapshot of every OS tid that
  belongs to the agent (accept thread + in-flight per-request workers).
  Maintained via `mark_agent(tid) -> AgentGuard`; the guard's `Drop`
  removes the tid when the thread exits, so the set converges as
  workers come and go.

### Changed
- **`/halts/wait` and `/halts` now emit identically-shaped lines**:
  `format_halt` always includes a trailing `\n` (matching `format_bp`).
  Previously `/halts/wait` returned a single line without a trailing
  newline while `/halts` did, so clients consuming both with line-
  oriented parsers needed a special case for one of them.
- **CLI `setregs` prints a TTY hint**: when stdin is a terminal,
  emits `(reading regs from stdin as 'name=value' lines; Ctrl-D to
  send)` to stderr so users running it interactively don't sit
  waiting for an invisible EOF.
- **Release workflow sanity-build**: the publish job now cross-
  compiles to `x86_64-pc-windows-gnu` and `i686-pc-windows-gnu`
  before `cargo publish --no-verify`. crates.io's environment can't
  compile those targets, so without this guard a publishable-but-
  broken commit would only fail for users on `cargo install`.
- **Injector switched to `LoadLibraryW`**: paths are encoded as UTF-16
  before being written into the target, so non-ASCII DLL paths work.
  Previously the path was forced through `to_str()` and rejected if
  not UTF-8 — fine for ASCII users, broken everywhere else.
- **Injector wait is now bounded at 30 seconds** (was `INFINITE`). If
  the remote `LoadLibraryW` thread doesn't complete in time the
  injector reports the timeout, leaks the remote path memory (the
  in-flight thread may still be reading it; freeing would be
  use-after-free), and exits non-zero with the offending tid + remote
  address so the user can investigate the wedged thread.
- **Injector pre-flights bitness with `IsWow64Process2`**: refuses
  with a clear error when the injector and target architectures differ
  (e.g. running x64 `haunt-inject.exe` against a 32-bit process). The
  previous behavior was a successful `CreateRemoteThread` followed by
  `LoadLibraryW` returning NULL inside the target with a vague "DLL
  not found or DllMain failed" message.
- `ThreadInfo.is_self` renamed to `is_agent` and now means what the
  README always claimed: true if the thread belongs to the agent.
  Previously the field was set from `GetCurrentThreadId()` of the
  worker handling the `/threads` request — useless and misleading.
  Output line now reads `agent=true` instead of `self=true`.
- All HTTP requests must include `X-Haunt-Client: <anything>` and must
  not have a non-empty, non-`null` `Origin` header. CSRF defence so a
  page in the user's browser can't fetch arbitrary memory or
  `POST /shutdown` cross-origin. CLI sets the header automatically;
  curl users add `-H 'X-Haunt-Client: curl'`.
- `thread_role::mark_agent()` now takes a `tid` and returns `AgentGuard`;
  callers must bind it (the `#[must_use]` lint catches `let _ = ...`
  drops). SemVer break against any out-of-tree consumer; in-tree the
  only caller paths are `core::run` and the per-request worker spawn,
  both updated.
- `MemError` variants: `Partial(usize)` is replaced by `Partial(Vec<u8>)`
  for read paths, with `PartialWritten(usize)` for write paths. SemVer
  break against any out-of-tree consumers of `haunt-core` (likely none
  in the 0.1.x window).

### Fixed
- **DSL stack overflow → host abort**: deeply nested `(...)`/`[...]` in a
  `--if`/`--log` expression would recurse without bound, blow the worker
  thread's stack, and (under `panic=abort`) kill the host. Added a 32-deep
  cap; over-deep input now returns a parse error rather than crashing.
- **`regions::search` out-of-bounds slice panic**: when the tail of a region
  was smaller than the pattern length, the chunk loop sliced past the read
  buffer and panicked. Reachable with any IDA-style pattern of length N over
  a region whose size mod `SEARCH_CHUNK` < N. Now skips the tail iteration.
- **`/shutdown` zombied threads parked in mid-flight halts**: the snapshot-
  then-resume sequence had a TOCTOU window where a hit could insert itself
  between the snapshot and the flag store, then sit in
  `WaitForSingleObject(INFINITE)` forever. `shutdown_halts` now sets the
  flag AND signals every parked event under the same mutex `halt_and_wait`
  uses for its check-and-park; teardown is atomic.
- **`SetEvent` on a closed handle from racing `/halts/<id>/resume`**: two
  concurrent resumes copied the same HANDLE, the parked thread woke on the
  first SetEvent and `CloseHandle`'d the event, and the second SetEvent
  fired on a closed (and possibly recycled) handle. SetEvent now runs
  inside the halts lock; the parked thread also closes its event under the
  same lock, ordering the wake-and-cleanup ahead of any second resume.
- **`events::push` self-deadlock under heap-allocator instrumentation**: a
  `--log` BP on `RtlAllocateHeap` (or anything in the events path's call
  graph) would recursively re-enter `events::push` on the same thread; the
  non-reentrant `Mutex<VecDeque>` deadlocked. Added a thread-local
  re-entry guard that drops the inner record.
- **Events ring lost records under concurrent `push`**: monotonic id was
  allocated before the ring lock, so two producers could insert in inverse
  id order and any consumer that advanced past the higher id permanently
  missed the lower one (`id > since` rejected it). Id is now allocated
  inside the lock so push order matches id order.
- **Hardware-BP propagation could deadlock the agent**: the `warn!` calls
  inside the `SuspendThread`/`ResumeThread` loop allocated via `format!`,
  and any suspended thread that held the process heap lock would freeze
  the agent permanently. Failures are now buffered onto a stack-friendly
  Vec and logged after `ResumeThread` for that tid.
- **SW BP install silently disabled an overlapping page BP**: planting an
  int3 byte requires `VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE)`,
  which strips `PAGE_GUARD` off the *whole* page (Win32 protections are
  page-granular); page-BP coverage went dark for the duration of the
  install and every rearm. `bp set` now rejects a SW BP whose page
  contains a page BP (and vice versa) with `409 Conflict`.
- **`expect("present, just verified")` in `breakpoint::clear`**: violated
  the project's no-panic policy. Replaced with an explicit `Err(Internal)`
  on the impossible branch so a future refactor can't turn it into a host
  crash.
- **`/halts/wait` had no timeout cap**: `events::poll` capped at 60s but
  `/halts/wait` did not, letting `?timeout=u64::MAX` pin a worker thread
  indefinitely. Now clamped at 60s in both `core` and the platform impl.
- **Partial memory reads dropped the readable bytes**: `MemError::Partial`
  carried only a count; the response body was `partial: N bytes readable`
  with the bytes themselves discarded. Partial now carries the readable
  prefix; the response is `206` with the prefix as the body.
- **Bearer auth scheme was case-sensitive**: RFC 7235 §2.1 says auth-scheme
  matches case-insensitively; clients sending `bearer …` got 401. Now
  case-insensitive on the scheme; constant-time comparison still applies
  to the token.
- **`parse_exports` could read past the loaded module**: forged or
  truncated PE headers could make pointer arithmetic walk off the end of
  the mapping into unmapped pages, AVing under `panic=abort`. All RVAs
  are now bounds-checked against module size; name strings cap at the
  remaining module bytes.
- **Hardware BPs firing on the same instruction dispatched in HashMap
  order**: non-deterministic across runs, surprising for users with
  `--if`-conditional halts. Now sorted by `BpId` (creation order).
- **`/bp/set` silently defaulted on malformed params**: `halt=garbage` →
  `halt=true`, `tid=abc` → no tid filter. Now `400`s on parse failure.

### Docs
- New "Halts and global locks" section in the README explaining that
  `--halt` on a thread holding the loader lock, heap lock, or COM
  apartment lock can deadlock the whole process (including the agent),
  with `--no-halt --log` recommended for instrumented allocator/loader
  paths and a recovery note pointing at `TerminateProcess`.
- `apply_current_thread` doc comment is now honest about the kernel
  syscall path (`OpenThread` / `Get`-`Set`-`ThreadContext` / `CloseHandle`)
  touching ntdll-internal sync that haunt doesn't control. Previously
  claimed "lock-free, no allocation" without qualification.

## [0.1.2]

### Added
- `GET /bp/<id>` + `haunt bp info <id>` — single-BP inspection. The
  response includes the original `--log <template>` and `--if <expr>`
  source text alongside hit count and options, so users can audit
  what a BP is doing without re-issuing it. `bp list` rows carry the
  same fields.
- **Memory pattern search**: `GET /memory/search?pattern=<hex>` +
  `haunt search "<pat>" [--module <name>] [--start 0x...] [--end 0x...]
  [--limit N]`. IDA-style hex bytes with `??` wildcards. Scans only
  committed, readable regions; chunks reads with `pat_len-1` overlap
  so boundary-straddling matches are still found. Replaces the
  "export PE → grep file offsets → convert RVA → VA" dance with a
  single command.
- **Real x64 stack walker**: `/halts/<id>/stack` on the 64-bit DLL now
  uses `RtlLookupFunctionEntry` + `RtlVirtualUnwind` over loaded
  modules' `.pdata`, so frame-pointer-omitted and leaf functions
  unwind correctly without PDB symbols. The x86 DLL keeps the EBP
  chain (PE32 has no `.pdata`); a PDB-aware x86 walker is roadmap.
  Closes the "stack walker is shallow, BB_ReadSteeringProperties /
  CmdDispatchSwitch are missing" complaint for x64 targets.
- `Process::stack_walk(hit_id, max_frames)` lifted onto the trait so
  the formatter lives in core and the unwinder lives next to its
  platform-specific tables (`.pdata` on x64, EBP chain on x86).
- `GET /symbols/lookup?addr=0x...` + `haunt addr <addr>` CLI: reverse
  lookup of an address to `module+0xoffset`. The `regs` output auto-
  annotates the same way for every register whose value falls in a
  loaded module — no more dropping into Python to compute
  `addr - module_base`.
- `haunt args <hit_id> --conv win64|sysv|thiscall|fastcall|stdcall|cdecl
  --count N` — pure CLI; reads regs + bulk-fetches the right stack
  slots based on the calling convention.
- **Tracing DSL** for breakpoints: `bp set ... --log "<template>" --if "<expr>"`.
  Templates substitute `%name` (register), `%[expr]` (deref + value),
  `%{expr}` (raw expression value), `%%` (literal). Conditions are full
  expressions; non-zero passes. Eval runs server-side in the VEH so a
  200+/sec `--no-halt --log ...` BP doesn't flood the wire.
- `GET /events?since=<id>&limit=N&timeout=<ms>` + `haunt events` CLI:
  4096-record ring buffer of `--log` hits, long-poll-able. Records carry
  `id` (monotonic), `bp_id`, `tid`, `rip`, `t=<ms>`, `msg=...`. Each
  hit also flows through the existing log pipeline (DebugView /
  WINEDEBUG / stderr).
- Range watchpoint as a recipe: page BP + `--no-halt` + `--log
  "writer=%eip"` answers "who is writing to this range?" without
  per-thread DR slots.
- `GET /threads` + `haunt threads` CLI: per-thread DR0–DR3 / DR7 state,
  whether the agent can `OpenThread` it, plus running counters of
  successful vs failed `DLL_THREAD_ATTACH` HW BP applies. Lets you
  diagnose "did my HW BP propagate to all threads?" without guessing.
- `wait` accepts `since=<hit_id>`: returns the **oldest** parked hit
  with `id > since`, so polling clients get deterministic in-order
  delivery instead of a random hash-bucket pick.
- Logging pipeline in `haunt-core::log`: `Level`, `Sink` trait, `FanOut`,
  `StderrSink`, `set_sink`/`set_level`/`emit`, plus `error!` / `warn!` /
  `info!` / `debug!` / `trace!` macros. Designed so a `FileSink` (or
  other backend) can be added without touching call sites.
- `OutputDebugString` sink in `haunt-windows`; installed alongside
  `StderrSink` in `DllMain` so records land in DebugView and stderr
  (visible under WINE with `WINEDEBUG=+debugstr`).
- `haunt-inject` routes errors and the success message through the same
  logging pipeline.
- 32-bit Windows builds: `haunt.dll` and `haunt-inject.exe` for
  `i686-pc-windows-gnu` so users can inject into 32-bit target
  processes. `binaries.yml` attaches them to the release as
  `haunt-x86.dll` and `haunt-inject-x86.exe`.

### Changed
- BP entries now hold `Arc<BpHooks>` so the VEH hot path clones in
  O(1) (refcount bump) rather than deep-cloning the parsed AST per
  hit. Matters for `--no-halt --log` BPs at high hit rates.
- Log macros (`info!`/`warn!`/`debug!`/`trace!`) now gate `format!()`
  on the configured max level — filtered records skip the
  allocation. Default level is `Info`, set higher via
  `log::set_level(Level::Warn)` to suppress per-hit allocations from
  trace BPs.
- Stack output appends `... (truncated at depth=N)` when the walker
  ran the full requested depth so consumers can distinguish "stack
  was that short" from "depth limit hit".
- Removed redundant aliases on the protocol surface: `oneshot` (use
  `one_shot`), `tid_filter` (use `tid`), and `if` query param (use
  `cond`). The CLI's `--halt` flag (which was the default anyway) was
  also removed; use `--no-halt` to override.
- Breakpoint module gains an `arch/` abstraction that swaps register
  field names (`Rip`/`Eip`, `Rsp`/`Esp`, 64-bit vs 32-bit `Dr*`) and
  `CONTEXT_DEBUG_REGISTERS` flag between x64 and x86.
- `haunt-core` stack walk reads pointer-width from `rbp`/`ebp` using
  `size_of::<usize>()`, so the walk works on both bitnesses.

### Fixed
- **HTTP server was sequential** — long-polling `wait` or `events` held
  every other endpoint hostage. `core::run` now spawns a thread per
  request so concurrent CLIs work as expected. Per-request workers
  also tag themselves as agent-owned so the self-halt protection
  below covers them.
- **Setting any BP on a function the agent itself called would
  deadlock the server** — the parked thread was the same one that
  needed to handle `resume`. Added a per-thread "agent" tag (set in
  every agent-spawned thread) and the VEH now refuses to halt
  agent-owned threads, auto-promoting to no-halt with a warn.
- **Duplicate SW BP at the same address silently corrupted the
  saved-byte tracking** — the second install would read the existing
  `0xCC` and remember it as "the original". `bp set` now rejects a
  duplicate at the same address with `409`.
- **`PENDING` thread-local was a single slot** — overlapping page +
  SW BPs on the same instruction would lose the page rearm (the int3
  handler overwrote it), silently disabling the page BP. Replaced
  with one slot per kind so both rearms can ride the same TF
  interrupt.
- **`/shutdown` didn't wake `wait` long-pollers** — they spun to
  their timeout. Added an atomic shutdown flag and cv broadcast;
  pollers now return `204` immediately. `halt_and_wait` also refuses
  to park during shutdown so a hit arriving mid-teardown doesn't
  zombie its thread.
- Per-hit `info!` in `emit_log_event` demoted to `debug!` so the
  default log level filters it out before `format!` runs. `--no-halt
  --log` BPs at high rate no longer go through the stderr lock or
  `OutputDebugStringA` per hit; recursion surface is much smaller if
  the user BPs a function the logging path uses.
- **`/halts/wait` was unreachable** — the dynamic `/halts/<id>/...`
  prefix matcher intercepted every `/halts/X` and routed it to a
  handler that tried to parse "wait" as a `u64`. The match arm at
  `(Method::Get, "/halts/wait")` was dead code. Restructured the
  dispatcher so static routes match first; dynamic prefix matchers
  only run for genuinely-dynamic paths. **This is the actual root
  cause of the original "wait --timeout returned invalid hit_id"
  report — the algorithm fix from the earlier review improved the
  function but the endpoint was never reached.**
- **HW BP multi-hit loop** would silently skip subsequent
  `--no-halt --log` BPs whenever an earlier BP in the same VEH
  invocation had `options.halt=true` but its `cond` evaluated to
  false (no halt actually happened). `run_hooks_then_maybe_halt` now
  returns whether it parked the thread; the loop only breaks on
  actual halts.
- **PE32 vs PE32+ on x86**: `parse_exports` was always reading
  `IMAGE_NT_HEADERS64`, even on the 32-bit DLL where loaded modules
  are PE32 with a smaller `OptionalHeader`. The result was that
  `bp set kernel32.dll!CreateFileW` on the x86 build silently
  resolved to garbage offsets. Now cfg-guarded to `IMAGE_NT_HEADERS32`
  on x86.
- **`bp clear` race**: physical state (int3 byte / PAGE_GUARD) is now
  restored BEFORE the registry entry is removed. Previously, between
  remove and restore, a thread executing the int3 / accessing the page
  would find no matching entry, propagate the exception, and crash the
  host. HW BPs were already race-tolerant (`slot_fired` with no entry
  benignly clears DR6).
- Page BP rearm and software BP rearm in the single-step handler now
  log on `VirtualProtect`/`write_byte` failure instead of silently
  leaving the BP broken.
- Page BP install rollback now logs each per-page restore failure so
  partial-rollback state is at least visible.
- `wait` was returning a non-deterministic hit at high BP rate
  (HashMap iter is unordered). Now returns the lowest qualifying
  `hit_id`, restoring `wait → regs → resume → wait` ordering.
- Hardware breakpoint thread propagation no longer silently swallows
  Win32 failures. `OpenThread`, `SuspendThread`, `GetThreadContext`,
  `SetThreadContext`, and `CreateToolhelp32Snapshot` failures all log
  with the offending tid + `GetLastError()`. Each `bp set --kind hw`
  now emits `hw apply: N updated, K skipped`.
- `resume <hit> --ret` no longer plants a one-shot SW BP at a junk
  address when called mid-function. The candidate return address is
  validated against the loaded module list; on mismatch the request
  warns and returns rather than 0xCC-ing arbitrary memory.
- Agent no longer silently exits when the HTTP bind fails; the error
  now appears in the log with the port and OS error.

## [0.1.1]

### Added
- Symbol-by-name breakpoints: `bp set kernel32.dll!CreateFileW` resolves
  server-side against module export tables.
- `GET /symbols/resolve?name=module!symbol` and `haunt resolve` CLI.
- Stack walking: `GET /halts/<hit_id>/stack?depth=N` walks the rbp chain
  and resolves each frame to `module+0xoffset`. `haunt stack <hit_id>`
  CLI.
- `binaries` workflow: on `v*` tags, cross-compiles `haunt.dll`,
  `haunt-inject.exe`, `haunt.exe` for Windows and attaches them to the
  GitHub release with SHA256SUMS.

### Changed
- `parse_query` now percent-decodes values, so symbols and parameters
  containing non-ASCII-safe characters (mangled C++/Rust names, `+`,
  `=`, etc.) round-trip correctly.
- `/modules/<name>/exports` percent-decodes the `<name>` path segment.
- `/bp/set` rejects passing both `addr` and `name` with `400`.

### Fixed
- `/bp/set` and `/symbols/resolve` return `400` for malformed names
  (missing `!`) instead of `404`; genuine not-found still returns `404`.
- CLI `stack --depth N` builds well-formed URLs even when `--depth` is
  specified more than once (last value wins).

### Docs
- README: `module!symbol` in examples, new `/stack` and
  `/symbols/resolve` endpoints, accurate description of the hardcoded
  loopback bind and how to reach the agent remotely via SSH tunnel.
- Added `AGENTS.md` with workspace target, cdylib safety invariants,
  and guidance to keep cross-platform logic in `haunt-core`.

## [0.1.0]

Initial release. Memory read/write, software/hardware/page breakpoints,
halt with register snapshot, resume/step/run-to-return, module and
export enumeration. x86_64 Windows only.
