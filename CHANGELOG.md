# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.1] - 2026-04-28

### Added
- **`haunt` CLI prebuilt for Linux and macOS.** The DLL and injector
  are Windows-by-construction, but the CLI is just loopback HTTP over
  `std::net` with no native deps — there's no reason it should only be
  available as `haunt.exe`. Each release page now also ships:
  - `haunt-linux-x64`, `haunt-linux-arm64` — musl-static, run on any
    Linux distro from kernel 2.6+ with no glibc / shared-lib deps.
  - `haunt-macos-x64`, `haunt-macos-arm64` — native Apple Silicon and
    Intel builds.
  Each artifact ships with a sibling `*.sha256` (formatted by
  `shasum -a 256` so a `sha256sum -c` from any host validates it).
  The Windows job retains its consolidated `SHA256SUMS` file so
  existing release-asset names are unchanged.

## [0.5.0] - 2026-04-28

### Changed
- **Trace + log ring capacity raised from 4 096 to 40 960 records.**
  At 4 096 a short burst from a high-rate `--log` BP could slide
  records off the front of the ring before a `/events` caller
  finished its setup round trip. The new bound matches the new
  `limit`/`tail` ceiling so a single call can drain the whole ring.
- **`MAX_LONG_POLL_TIMEOUT_MS` raised from 60 000 to 300 000 ms (5 min).**
  Operators tailing `/events` or `/logs` over a slow link no longer
  have to re-poll every minute. Both the HTTP-edge validator and the
  platform-side `wait_halt` / `events::poll` / `logs::poll` impls
  enforce the new ceiling.
- **CLI socket read timeout raised from 90 s to 310 s.** Previous
  value pre-dated the long-poll cap bump; `--timeout` values above
  ~90 s would have the CLI's `TcpStream` abort the read before the
  agent could respond. New value covers the 300 s agent ceiling
  plus loopback slack.

### Added
- **`MAX_TRACE_BATCH` shared constant** as the single source of truth
  for both the events / logs ring capacity and the HTTP-edge `limit`
  / `tail` validator. The previous duplicated `4096` literal in
  `handle_events` / `handle_logs` would silently cap clients to the
  old value if the ring grew without the validator being touched.

### Documentation
- README's `Concurrency` paragraph now lists `/logs` alongside
  `/halts/wait` and `/events` as endpoints sharing the 64-of-80
  long-poll sub-cap (the classifier already routed `/logs` there;
  the prose was stale).
- CLI `USAGE` for `events` and `logs` now spells out the `--limit`
  default (256) and max (40960 = ring size); previously users only
  learned the bound from a 400 response.

## [0.4.0] - 2026-04-27

### Changed (breaking)
- **Strict-validation tightening across the HTTP surface.** Per the
  threat-model note added to AGENTS.md (we share an address space with
  the host; auth is not load-bearing, *correctness* is), every silent
  acceptance path is now a `400`:
  - **Unknown query parameters are rejected** by every endpoint that
    iterates query (e.g. `/bp/set?halft_if=...` — typo of `halt_if` —
    used to silently set a BP with no halt gate; now 400 names the
    offending key). `parse_resume_mode("foo=bar")` now errors instead
    of defaulting to `Continue`.
  - **No-arg endpoints reject any query.** `/ping?foo=1`, `/info?x=y`,
    `/modules?stale=1`, `/halts?...`, `/threads?...`, `/memory/regions?...`,
    `/bp/list?...`, `/shutdown?...`, `/bp/<id>?...`, and
    `/modules/<name>/exports?...` all 400 when given any params.
  - **Malformed query pairs are rejected at the dispatcher.** `?foo`
    (missing `=`) used to be silently dropped by `parse_query`; now
    `route()` 400s with `malformed query pair (expected key=value):
    \`foo\``. Single source of truth — handlers don't have to recheck.
  - **No more silent `clamp` on user-supplied counts.** `events`/`logs`
    `?limit=0` was silently raised to 1; `?limit=99999` was silently
    capped to 4096; `events` `?tail=0` was silently raised to 1; same
    for `tail` upper bound. All four cases now 400 with a message that
    names the parameter and the legal range. `/halts/<id>/stack?depth=0`
    likewise. `/halts/wait?timeout=...` and `/events`/`logs?timeout=...`
    over `MAX_LONG_POLL_TIMEOUT_MS` (60 s) now 400 instead of being
    clamped (the platform layer still re-clamps defensively in case a
    direct caller bypasses the HTTP edge).
  - **`/memory/read?format=` rejects unknown values.** Previously
    anything other than `raw` was silently treated as `hex`; now
    `format=hax` 400s rather than yielding hex output.

### Fixed
- **`resume --ret` now logs SW-BP install failure.** The one-shot SW
  BP planted at `[xSP]` was installed via `let _ = super::set(...)`
  — any `Conflict`/`Unwritable`/etc. error was silently dropped and
  the user got `200 resumed` while the thread ran free past the
  function with no halt. Now `warn!`s with the failure reason, visible
  via `haunt logs`.
- **`reject_page_covering_sw_bp` overflow.** The neighbouring
  `page_addr.checked_add(page_size)` correctly rejected wrap, but
  `end.saturating_add(ps - 1) & !(ps - 1)` could wrap `end_page` down
  past `end` and silently miss a SW BP on the last covered page. Now
  uses `checked_add` symmetrically with `page::install`.
- **`dsl::render` no longer `unwrap`s `write!` to a `String`.** The
  unwrap was infallible in practice (`fmt::Write for String` never
  errors) but violated the no-`unwrap` policy; a future refactor that
  swapped the sink for something fallible would have turned a render
  bug into a host-process abort. Now uses `let _ = write!(...)`.

### Docs
- **AGENTS.md threat model section.** Codifies that haunt's threat
  model is the host process (not network attackers): we share the
  address space, every silent default is a host bug, every panic kills
  the host. Strict validation, panic-free hot paths, no `unwrap`, no
  `unwrap_or` on user input, no silent defaults — non-negotiable.

### Added
- **`events --tail N`** returns the most recent `N` matching records
  in chronological order, regardless of `--since`. Disables long-poll
  (a snapshot, not a wait). Solves the ring-overflow foot-shape where
  `--since=0` slid off the front of the deque while the caller was
  setting up. Server: `?tail=N` query param; long-poll suppressed when
  set.
- **`events --bp-id N`** server-side filter — only records from BP
  `N` come back, useful when several BPs fire at high rate and the
  client only cares about one. Server: `?bp_id=N` query param.
- **CLI-side address annotation in `haunt events` / `haunt logs`.**
  Hex sequences in record `msg` fields that fall inside a loaded
  module are annotated inline as `0x... (module+0xoffset)` against
  `/modules`. Default-on; `--no-annotate` for stable output in
  scripts. Done CLI-side rather than VEH-side because module
  enumeration takes the loader lock — calling it from the VEH (where
  `--log` records are emitted) is a deadlock vector we deliberately
  avoid for the same reason `resume --ret` was moved off
  `modules::list` to `VirtualQuery`.

### Changed
- **`--if` split into `--log-if` and `--halt-if`.** The original
  single `cond` gate covered halt + log + event uniformly. Splitting
  lets a single BP log every call but halt only on a specific
  predicate (e.g. `--log "..." --halt-if "[ecx] == 0x..."`). Per the
  AGENTS.md no-compat policy, `--if` is removed; HTTP `?cond=` is
  removed in favour of `?log_if=` and `?halt_if=`. `bp list` /
  `bp info` output now has `log_if=...` and `halt_if=...` fields in
  place of `cond=...`. `entry.hits` continues to count every fire
  regardless of either gate.

### Added
- **`GET /logs` endpoint and `haunt logs` CLI** for tailing the agent's
  own `info!` / `warn!` / `error!` output. Mirrors `/events`: bounded
  ring (4096), monotonic id, long-poll up to 60 s, same `?since=&limit=
  &timeout=` query shape. Replaces the previous `OutputDebugStringA`
  sink, which could **block the agent** when a debugger was attached but
  not draining the LPC queue, mixed output across every process on the
  box, and required DebugView / a real debugger to consume. The new
  endpoint flows through the same auth / CSRF / in-flight-cap machinery
  as everything else and works over SSH the same way.

### Removed
- **`OutputDebugStringA` log sink** in `haunt-windows` (`DebugStringSink`).
  Use `haunt logs` to drain the agent's output instead.

### Fixed
- **Step → continue from a HW BP halt no longer kills the host.**
  `apply_resume_mode(Step)` set `TRAP_FLAG`; nothing cleared it on the
  subsequent `Continue` (HW BP path doesn't have a rearm to consume
  TF, unlike the SW / page paths). The thread resumed with TF=1, the
  next instruction TF-trapped, `on_single_step` found no rearm / no
  `STEP::Step` / no DR slot fired, fell through to `EXCEPTION_CONTINUE_
  SEARCH`, and the OS unhandled-exception filter terminated the host.
  Reachable from the routine "halt at HW BP, single-step a few times,
  continue" workflow. Fixed by clearing TF unconditionally at entry to
  `on_single_step` (with `apply_resume_mode(Step)` re-setting it as the
  only legitimate post-handler use). The same bug bit any "step ...
  step ... continue" sequence, not just HW BPs.
- **Multi-page accesses no longer lose page-BP rearms.**
  `PENDING_PAGE` was a single `Cell<Option<PageRearm>>`. A misaligned
  load crossing a page boundary, `rep movs` over multiple pages, or
  any instruction that traps on more than one guarded page in
  succession would overwrite the earlier rearm — silently turning the
  BP one-shot for every page after the first on the very first multi-
  page hit. Now a `Cell<Vec<PageRearm>>` (capped at 64 entries; uses
  `Cell::take` / `Cell::set` rather than `RefCell` to stay panic-free).
- **Failed page-BP installs no longer leak `PAGE_GUARD` orphans.**
  Two paths produced orphan-guarded pages with no registry entry,
  killing the host on the next access: (1) `query_protect` failure
  mid-loop bailed via `?` with no rollback, leaking guards on every
  already-protected page; (2) `set_protect` failure rolled back, but
  if a rollback `VirtualProtect` itself failed the page stayed
  guarded. Both paths now go through one rollback that records any
  unreversible page in `ORPHAN_PAGES`. The VEH consults the set on a
  guard fault that doesn't match any registered BP and returns
  `EXCEPTION_CONTINUE_EXECUTION` instead of propagating to a host
  kill. Capped at 4 K entries with arbitrary eviction so a degenerate
  workflow can't grow the set unboundedly.
- **SW BP install rejects pages that already have `PAGE_GUARD` set.**
  `write_byte`'s `VirtualProtect(PAGE_EXECUTE_READWRITE)` is page-
  granular and silently strips `PAGE_GUARD` for the duration of the
  byte write — defeating the OS stack-growth guard, AV sentinels, JIT
  runtime traps, and foreign debuggers using `PAGE_GUARD`. Now
  `VirtualQuery`-checked at install time and rejected with `Conflict`
  / `409`. Symmetric with `reject_sw_overlapping_page_bp` (which
  catches haunt's own page BPs); this catches third-party guards.
- **`clear()` racing an in-flight SW BP hit no longer kills the host.**
  `clear()` could restore the original byte and remove the registry
  entry between the int3 firing and `on_int3` acquiring the registry
  lock. The CPU's saved IP points past the int3 byte (int3 is a trap),
  so resuming as-is would skip the original instruction (single-byte)
  or land mid-instruction (multi-byte). `on_int3` now reads the byte
  via `ReadProcessMemory` on a missed lookup: if it's no longer
  `0xCC`, rewind IP to the original-byte address and `CONTINUE_
  EXECUTION` so the original instruction re-executes. If the byte is
  still `0xCC`, propagate (compiler-emitted int3, third-party hook).
- **`clear()` racing an in-flight page BP fault no longer kills the
  host.** Symmetric race: `clear()` restored protections and removed
  the entry while another thread was parked in `on_guard_page` waiting
  for the registry lock. After `page::restore` (under the lock),
  `clear()` now marks each affected page in `ORPHAN_PAGES` so the
  racing thread recovers via the orphan path on the next lookup. The
  marker is consumed by the first `take_orphan` call.
- **`read_cstr_bounded` clamps by readable region as well as length.**
  The 4 KB hard cap limited *how many* bytes we'd walk but not whether
  the bytes were mapped. A malformed PE — or a normal PE with the
  export string table abutting an unmapped page — would let
  `from_raw_parts(ptr, 4096)` AV partway through the NUL scan. Now
  also bounds by `VirtualQuery`'s region tail, returning `None` if the
  page is uncommitted, `PAGE_NOACCESS`, or `PAGE_GUARD`.
- **`PENDING_PAGE` survives thread-local teardown.** `Cell<Vec<...>>`
  has a destructor; the thread-local runtime runs it at thread exit.
  After that, `LocalKey::with` panics — which under `panic = "abort"`
  kills the host. A SW BP on a function called from another DLL's
  `DLL_THREAD_DETACH` could fire inside that window. Switched the
  push/drain sites to `try_with`, silently treating the page-rearm
  buffer as empty when it's gone (correct degradation: the page BP
  becomes one-shot for this teardown-bound thread).
- **`haunt read` / `haunt read-raw` surface partial-content responses.**
  The agent returns `206 Partial Content` with the readable prefix when
  a `/memory/read` crosses an unmapped page; the CLI's `request()`
  collapsed every 2xx to "success, here's the body," so a truncated read
  printed the prefix to stdout with no signal that fewer bytes than
  requested came back. Added a `request_full` helper that exposes the
  HTTP status; `cmd_read` now writes a stderr warning of the form
  `read truncated at unmapped boundary: N/M bytes returned`.
- **`resume --ret` no longer takes the PEB loader lock.** The validation
  that `[xSP]` points into executable code went through `modules::list()`
  → `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ...)`, which acquires
  the loader lock — running from the VEH path on the resuming thread,
  this created a deadlock vector if any other thread was simultaneously
  in our VEH blocked on the registry lock while holding the loader lock
  (e.g., faulted inside `LdrpLoadDll`). Replaced with a single
  `VirtualQuery` checking for committed, executable, non-`PAGE_GUARD`
  memory. As a side effect, run-to-ret now also accepts JIT regions
  (V8, .NET CLR, JVM, runtime-patched code) — the previous module-only
  check rejected them.
- **Page BPs on data pages no longer crash the host.** `on_guard_page`
  dispatched off `record.ExceptionAddress`, which is the *instruction
  pointer* at fault time. For read/write watchpoints on data pages the IP
  sits in the code segment (not the guarded page), so `find_containing`
  returned `None`, the handler returned `EXCEPTION_CONTINUE_SEARCH`, and
  the OS terminated the host. Now reads `ExceptionInformation[1]` (the
  actual address that tripped PAGE_GUARD), with a `NumberParameters >= 2`
  guard.
- **TOCTOU between `find_containing` and the entry-mutation lock in
  `on_guard_page`.** The handler took the registry lock, looked up the
  page, dropped the lock, then re-acquired to bump hits. A concurrent
  `clear()` in the gap left no entry on the second lookup → `CONTINUE_
  SEARCH` → host kill (PAGE_GUARD already auto-cleared). Folded into a
  single lock acquisition.
- **`set_breakpoint` on a byte already containing `0xCC` is rejected.**
  The previous install would record `0xCC` as the original byte; on the
  first hit, `on_int3` would restore "the original" (still `0xCC`), the
  CPU would re-execute it, raise `EXCEPTION_BREAKPOINT` again, and loop
  forever — TF never gets a chance because the int3 fires before the
  single-step. Now returns `Conflict`.
- **Worker thread spawn failure no longer aborts the host.** The accept
  loop used `std::thread::spawn`, which is `Builder::new().spawn().
  unwrap()` — under handle/quota exhaustion the unwrap panicked, and
  `panic = "abort"` killed the host. Now uses `Builder::spawn` and logs
  the failure, dropping the request (slot guard's Drop releases the
  counter).
- **`page::install` integer overflow.** `(end + ps - 1)` was unchecked;
  for `addr` near `usize::MAX` it wrapped to a small value, `end_page`
  became 0, and the install loop ran zero iterations — a silently-empty
  page BP that never fires. Now uses `checked_add`.
- **`AddVectoredExceptionHandler` failure surfaced as `BpError::
  Internal`.** Previously the NULL return was discarded; every BP became
  a no-op that propagated to the OS default handler and crashed the
  host. The install result is now stored in the `OnceLock` so subsequent
  callers see the same failure rather than re-running the closure (which
  `get_or_init` only does once).
- **HW BP snapshot publication races on enable and disable.** Atomic
  ordering was Relaxed; a new thread's `DLL_THREAD_ATTACH` could observe
  `SNAP_DR7` enabled without observing the matching `SNAP_DR[slot]`
  (enable: stale slot value; disable: BP at address 0). `SNAP_DR7`'s
  CAS is now Release / Acquire-paired with the reader, and disable
  inverts the publish order (DR7 cleared first, DR[slot]=0 second) so a
  reader can never see "DR7 enabled + DR[slot]=0".
- **`apply_to_all_threads` skips agent worker threads, not just
  `tid_self`.** A HW BP on, e.g., `ntdll!RtlAllocateHeap` previously
  applied to every agent worker; VEH refused to halt them but still
  emitted log/event records, flooding the rings on every internal
  allocation.
- **`events::shutdown()` and `logs::shutdown()` now actually unblock
  pollers.** The previous implementation just `notify_all`-ed; pollers
  woke, found nothing changed, re-checked their (still pending) deadline,
  and `wait_timeout` again — they'd block until their per-call timeout
  (≤60 s). Mirrors the `shutting_down` flag pattern already used in
  `breakpoint::halt::shutdown`.
- **`read_cstr_bounded` capped at 4 KB.** Walking byte-by-byte through
  `module_size` bytes to find a NUL would AV inside the agent if the
  module mapping had an unmapped hole — fatal under `panic = "abort"`.
  Real export names and forwarder strings are well under 4 KB.
- **`halt_and_wait` distinguishes "parked then resumed" from "could not
  park".** Returns `Option<ResumeMode>` instead of falsely reporting
  `Continue` on event-creation failure / shutdown / lock poisoning. The
  HW-BP dispatch loop in `on_single_step` no longer breaks early on a
  halt that didn't actually happen, so subsequent BPs that fired on the
  same instruction get their hooks run.
- **`apply_to_all_threads` failure Vec pre-reserved.** Suspended-thread
  paths still don't push, but pre-reserving documents the
  no-realloc-while-suspended invariant defensively for future edits.
- **`setregs` is now a merge, not a destructive overwrite.** The previous
  flow built a default-zeroed `Registers` from the parsed body and applied
  it whole, so `printf 'rax=0\n' | haunt setregs N && haunt resume N`
  zeroed `rip`, `rsp`, and every other register the user did not name —
  resuming the thread into a guaranteed crash. `parse_regs` now returns a
  `Vec<(RegName, u64)>` patch; `Process::halt_set_regs` merges under the
  same lock as `resume()` so there's no race window. Unknown register
  names return `400` with the offending name instead of being silently
  dropped (previous behaviour combined with the overwrite turned typos
  into target-process crashes).
- **`POST /halts/<id>/regs` body capped at 64 KB.** The handler used
  `read_to_string` with no upper bound; a malicious or buggy multi-GB
  POST allocated without limit, and `panic = "abort"` turned the OOM into
  a host-process kill.
- **HW breakpoint slot reuse race fixed.** `set_hardware`/`clear` now
  hold the registry lock across `apply_to_all_threads`, serialising the
  DR-mutation sweep with any concurrent install/uninstall. Previously a
  `clear()` of one HW BP racing a `set()` of another could leave the new
  BP marked installed in the registry while its DR slot was zeroed by
  the loser-runs-second sweep.
- **DR7 LE bit no longer diverges between snapshot and per-thread
  CONTEXT.** A latent bug in the per-CONTEXT writer left `LE=1` after
  the last slot was disabled, while the atomic snapshot correctly cleared
  it. New threads (which read the snapshot in `DLL_THREAD_ATTACH`) and
  existing threads disagreed. Both paths now share `encode_dr7_slot`.
- **CLI `args` no longer panics on partial reads.** A `206` (partial
  content) on the bulk stack-slot fetch produced a `try_into().unwrap()`
  panic; the truncation now reports on stderr and the readable args
  print normally.

### Changed (breaking)
- **Strict validation across the board.** Per the new policy in
  `AGENTS.md`, every parameter that takes a constrained value rejects
  unrecognised input with a `400` and a message that names the offending
  parameter. Previously many handlers fell back silently to defaults.
  Specific cases:
  - `POST /halts/<id>/resume?mode=<x>` rejects `mode=` other than
    `continue|step|ret`.
  - `GET /halts/<id>/stack?depth=<x>` rejects non-numeric `depth`.
  - `POST /bp/set?kind=sw&access=...` and `?kind=sw&size=...` reject
    `access`/`size` (only valid with `kind=hw` or `kind=page`).
  - `POST /bp/set?kind=page&access=...` rejects `access` entirely
    (PAGE_GUARD has no per-kind selectivity).
  - `GET /events?since=&limit=&timeout=` and
    `GET /memory/search?start=&end=&limit=` reject non-numeric values
    (previously fell back to defaults).
  - `GET /memory/read?addr=&len=` and `POST /memory/write?addr=` and
    `GET /symbols/lookup?addr=` and `POST /bp/clear?id=` likewise.
  - CLI `haunt resume <id> [--continue|--step|--ret]` rejects unknown
    flags and conflicting mode flags.
  - `parse_access` no longer accepts the undocumented `r` alias for
    `any`.
- **`BpKind::Page` no longer carries an `access` field**; PAGE_GUARD
  fires on any access kind, and the field was already ignored. `bp list`
  output for page BPs is now `page/size=N` (was `page/any/size=N`).
- **`/halts/<id>/regs` POST body** is parsed as a patch, not a full
  register snapshot; both `rax` and `eax` (and the other r* / e*
  spellings) are accepted, and the merge happens platform-side.
- `MAX_LONG_POLL_TIMEOUT_MS` is the single source of truth for the 60 s
  long-poll cap (was duplicated as `MAX_WAIT_TIMEOUT_MS` and
  `MAX_TIMEOUT_MS` across `core/lib.rs`, `windows/breakpoint/halt.rs`,
  and `core/events.rs`).
- `bp set` success response now ends with `\n`, matching every other
  line-formatted endpoint.

### Internal
- The `_Unwind_Resume` stub for i686-pc-windows-gnu lives once in
  `haunt-core` instead of being duplicated in every binary crate.
- DR7 bit-encoding extracted to `encode_dr7_slot()` in
  `windows/breakpoint/hardware.rs`.
- CLI URL-encodes the addr parameter on `bp set`, `read`, `read-raw`,
  `write` (was raw, so a typo containing `&`/`+`/`%` would have
  corrupted the query).

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
