# haunt

> 100% AI-developed.

A debugger-as-an-HTTP-server. Inject `haunt.dll` into a Windows
process; drive it with the `haunt` CLI or any HTTP client. Memory
read/write, software/hardware/page breakpoints, halt with register
snapshot, resume/step/run-to-return, server-side trace DSL — over a
flat REST surface with no runtime dependencies on the target.

## Status

- Windows x86_64 and x86 (32-bit).
- Breakpoint kinds: software (`int3`), hardware (DR0–DR3), page
  (`PAGE_GUARD`).
- Hardware BPs propagate to new threads via `DLL_THREAD_ATTACH`
  (`SetThreadContext` on self — documented-fragile but empirically
  reliable on modern Windows).
- `panic = "abort"`; agent is audited for `unwrap`/`expect`. Memory
  R/W goes through `ReadProcessMemory`/`WriteProcessMemory`, so bad
  addresses return errors instead of crashing the host.
- Stack walking: x64 uses `RtlLookupFunctionEntry` +
  `RtlVirtualUnwind` against `.pdata` (FPO-safe, no PDBs). x86 PE32
  has no `.pdata` — falls back to the EBP chain, so frames may be
  missing on FPO functions. PDB-aware x86 walker is roadmap.

## Layout

```
crates/
├── core/      haunt-core      platform-agnostic HTTP + protocol
├── windows/   haunt-windows   cdylib → haunt.dll
├── inject/    haunt-inject    CreateRemoteThread(LoadLibraryW)
└── cli/       haunt           haunt.exe
```

## Build

Requires Rust (`rustup`) and MinGW-w64 (cross-compiles from macOS/Linux to Windows).

```sh
brew install mingw-w64        # macOS; apt install gcc-mingw-w64-x86-64 on Debian
./build.sh                    # haunt.dll only
cargo build --release         # all artifacts
```

Output ends up in `target/x86_64-pc-windows-gnu/release/`:

- `haunt.dll` — the agent (~400 KB, system DLLs only)
- `haunt-inject.exe` — loader
- `haunt.exe` — CLI client

For 32-bit targets: `--target i686-pc-windows-gnu` (also covered by
`brew install mingw-w64`; `rustup target add i686-pc-windows-gnu`).
Only `haunt-windows` and `haunt-inject` are relevant; the CLI is
bitness-agnostic. CI publishes 32-bit artifacts as `haunt-x86.dll`
and `haunt-inject-x86.exe`.

## Quick start

```sh
haunt-inject --pid 1234 .\haunt.dll
set HAUNT_URL=http://127.0.0.1:7878

haunt info                              # version, arch, pid, uptime
haunt modules                           # list loaded modules
haunt resolve kernel32.dll!CreateFileW  # name → address
haunt addr 0x7FFE12340000               # address → module+offset

haunt bp set kernel32.dll!CreateFileW
haunt wait                              # blocks until a thread halts
haunt regs 1
haunt resume 1
```

The injector pre-flights bitness via `IsWow64Process2`; mismatched
injector ↔ target arch fails fast with a clear message rather than a
silent NULL `LoadLibraryW`.

## Workflows

`HAUNT_URL` set; agent injected.

**Trace a function call.** `bp set <module>!<symbol>` resolves the
name via `GetProcAddress`, so forwarders (`kernel32!ExitProcess` →
`ntdll!RtlExitUserProcess`) and API-set redirection follow. The
response echoes the resolved address.

```sh
haunt bp set kernel32.dll!CreateFileW
haunt wait                             # yields hit_id
haunt regs 3                           # args in rcx/rdx/r8/r9 on win64
haunt stack 3                          # backtrace, module+offset resolved
haunt read 0x14FE3C0000 64             # dereference a pointer arg
haunt resume 3
```

`haunt args <hit_id> --conv win64|sysv|thiscall|fastcall|stdcall|cdecl
[--count N]` reads registers + the right stack slots in one shot.
Default `--conv` is `win64` on x64 agents, `cdecl` on x86 (queried
from `/info`).

**Find a code pattern.** IDA-style hex bytes; `??` = wildcard. A
scope is required (`--module`, `--start/--end`, or `--all`):

```sh
haunt search "48 89 ?? ?? c3" --module CryGame.dll --limit 16
```

`--all` opts into a whole-AS scan — slow on multi-GB targets, no
progress, no cancel.

**Patch a return value.** Halt at the `ret`, overwrite `rax`,
resume. `setregs` merges into the parked thread's saved CONTEXT —
registers you don't name keep their captured values. Either x64 (`rax`)
or x86 (`eax`) names work; unknown names return `400` instead of being
silently dropped.

```sh
haunt bp set 0x7FF601234ABC --kind sw --one-shot
haunt wait
printf 'rax=0\n' | haunt setregs 7
haunt resume 7
```

**Watch a field for writes.** Hardware BP with `--access w`. Auto-
propagates to new threads.

```sh
haunt bp set 0x00007FF6DEADBEEF --kind hw --access w --size 4
haunt wait --timeout 60000
haunt regs 12                          # rip points at the writing instruction
haunt resume 12
```

**Non-halting tripwire.** `--no-halt` records hits without parking
the thread — sample hot paths via hit count.

```sh
haunt bp set 0x7FF601234000 --no-halt
haunt bp list                          # hit counts per BP
```

**Trace at line rate (dtrace-style).** `--log <template>` evaluates
on every hit and emits to a 4096-record ring buffer. `--log-if` and
`--halt-if` are independent gates: log/event emission and halt are
controlled separately, so a single BP can log every call and halt
only on the runs that match a condition.

```sh
# Log ecx and *(ecx+8) on every call to a 200/sec hot function:
haunt bp set CryGame.dll!OnPacket --no-halt \
  --log "ecx=%ecx [ecx+8]=%[ecx+8]"

# Halt only when a specific value flows through (no --log gate, so
# halt fires only when the predicate passes — original --if behaviour):
haunt bp set 0x7FF601234ABC --halt-if "ecx == 0x281"

# Log every call, halt only on a specific run:
haunt bp set CryGame.dll!OnPacket \
  --log "type=%ecx [esp+4]=%[esp+4]" \
  --halt-if "[ecx] == 0x11D1F298"

# Show the most recent 10 records — no since-dance, no long-poll:
haunt events --tail 10

# Tail the ring buffer with long-poll, filtered to one BP:
haunt events --since 0 --timeout 5000 --bp-id 4
```

Template syntax: `%name` = register, `%[expr]` = deref + value,
`%{expr}` = raw value, `%%` = literal `%`. Expressions:
`+ - * & | ^ << >> ~ == != < <= > >= ()` over hex/decimal literals,
register names, and `[deref]` subexpressions. Both gate predicates
take the same syntax; non-zero passes. Parser depth is capped at 32
levels. `entry.hits` increments on every fire regardless of either
gate (raw fire count).

`haunt events` and `haunt logs` annotate hex addresses inline as
`(module+0xoffset)` against `/modules`; pass `--no-annotate` for
stable output in scripts.

**Range watchpoint.** Page BP + `--no-halt` + `--log` answers "who
writes into this range?":

```sh
haunt bp set 0x00007FF6DEADBEEF --kind page --size 0x1000 --no-halt \
  --log "writer=%eip"
sleep 5
haunt events --since 0 --limit 4096 > writers.log
haunt bp clear <id>
```

## Halts and global locks

Halting a thread that holds a process-wide critical section can
deadlock the entire process — including the agent, which shares the
target's address space and locks. The halt mechanic parks the firing
thread on `WaitForSingleObject(INFINITE)` while it keeps holding
every lock it had at the moment of the BP.

The locks that bite:

- **Loader lock** — held inside `LoadLibrary`, `FreeLibrary`, every
  `DllMain`. A halt here freezes future thread spawns process-wide,
  including the agent's per-request workers.
- **Heap lock** — held inside `RtlAllocateHeap` and therefore inside
  every `malloc`, every Rust allocation, every Win32 API that
  allocates. The agent allocates on every request; within seconds it
  wedges.
- **COM apartment locks** — held during STA marshaling. Same shape
  of failure for COM-heavy targets.

For instrumentation on these paths, use `--no-halt --log`. The log
record renders inline from the VEH; the lock is held for
microseconds, not indefinitely.

```sh
# DON'T — halts inside the heap critical section:
haunt bp set ntdll.dll!RtlAllocateHeap

# DO — fires, logs the size, returns immediately:
haunt bp set ntdll.dll!RtlAllocateHeap --no-halt --log "size=%rdx"
```

`--halt` (the default) is generally safe at function entry of
external API calls — internal locks are taken AFTER entry — and on
code that doesn't itself allocate, take a global lock, or call into
the loader.

If a halt deadlocks the target, `/shutdown` cannot recover the
process; the HTTP server itself is blocked allocating its response.
Only `TerminateProcess` from outside (Task Manager,
`taskkill /F /PID <pid>`) gets you out.

The agent refuses to halt its own threads (auto-promotes to no-halt
with a warning), but cannot detect that some other thread holds a
lock the agent will need next. Others face the same problem and
handle it the same way: document the risk.

## Protocol

HTTP/1.1 plain text. Bound to `127.0.0.1:7878` (loopback only, not
configurable).

**Auth.** Opt-in via `HAUNT_TOKEN`: set in the **target process's**
environment before injection, then pass
`Authorization: Bearer <token>` from the client. Constant-time
comparison; scheme is case-insensitive.

**CSRF.** Every request must include `X-Haunt-Client: <anything>`.
The CLI sets this automatically. curl adds it explicitly:

```sh
curl -H 'X-Haunt-Client: curl' http://127.0.0.1:7878/ping
```

Browsers can't send custom headers on simple cross-origin requests
without CORS preflight (which the agent doesn't support), so a
missing header indicates either a non-CLI client or a malicious
page. The agent also rejects requests with a non-empty, non-`null`
`Origin` header.

**Concurrency.** One worker thread per request, capped at 80 total.
Long-poll endpoints (`/halts/wait`, `/events`) share a sub-cap of
64; the remaining 16 slots stay reserved for short requests so a
stuck poll loop can't lock you out of `bp clear`/`resume`/`regs`.
Over either cap returns `503 too busy`.

**Remote.** Drive from another machine via SSH (also encrypts the
wire — the protocol has no TLS):

```sh
ssh -L 7878:127.0.0.1:7878 <target-host>
HAUNT_URL=http://127.0.0.1:7878 haunt ping
```

### Endpoints

Memory:
- `GET  /memory/read?addr=0x...&len=N[&format=hex|raw]` — partial reads return `206` with the readable prefix
- `POST /memory/write?addr=0x...` (raw body)
- `GET  /memory/regions`
- `GET  /memory/search?pattern=<hex>{&module=<name>|&start=0x...&end=0x...|&all=true}[&limit=N]` — IDA-style hex; `??` = wildcard. Scope required.

Breakpoints:
- `POST /bp/set?{addr=0x...|name=module!symbol}&kind=sw|hw|page[&access=x|w|rw|any][&size=N][&halt=true|false][&one_shot=true][&tid=N][&log=<template>][&log_if=<expr>][&halt_if=<expr>]`
  - `access`: `x`/`exec`, `w`/`write`, `rw`/`readwrite`, `any`. HW
    requires `size ∈ {1,2,4,8}` (8 is x64-only) and `addr` aligned
    to `size` for `size > 1`. Page rounds `size` up to whole pages.
  - SW and page BPs covering the same page are rejected with `409
    Conflict` (the SW install momentarily strips `PAGE_GUARD`). A SW BP
    on a byte that already contains `0xCC` (compiler-emitted `int 3`,
    third-party hook, etc.) is rejected with the same status — installing
    would record `0xCC` as the original byte and infinite-loop on the
    first hit. A SW BP on a page that already has `PAGE_GUARD` set
    (target's own stack-growth guard, antivirus sentinel, foreign
    debugger) is also rejected — the install's `VirtualProtect` would
    silently strip the guard for the duration of the byte write.
  - Response: `id=N addr=0x...` so name resolution is auditable.
- `POST /bp/clear?id=N`
- `GET  /bp/list` and `GET /bp/<id>` — entries include `requested=...` for BPs set by name

Trace events:
- `GET  /events?since=<id>&limit=N&timeout=<ms>[&bp_id=<id>][&tail=<n>]` — `since`/`timeout` long-polls up to 60 s; `tail=n` returns the most recent `n` matching records and disables long-polling; `bp_id` filters server-side.

Agent logs:
- `GET  /logs?since=<id>&limit=N&timeout=<ms>` — agent's own info/warn/
  error output (bind status, BP install reports, VEH warnings) over a
  4096-record ring, long-polls up to 60 s. Replaces `OutputDebugString`
  (which could block the agent if a debugger was attached but not
  draining, and mixed output across every process on the box).

Halts:
- `GET  /halts`
- `GET  /halts/wait?timeout=<ms>&since=<hit_id>` — oldest hit with `id > since`; long-polls up to 60 s
- `GET  /halts/<hit_id>` — register dump; values pointing into a loaded module are auto-annotated as `module+0xoffset`
- `GET  /halts/<hit_id>/stack[?depth=N]` — backtrace; default 32, max 256
- `POST /halts/<hit_id>/regs` (body: `name=value` lines)
- `POST /halts/<hit_id>/resume?mode=continue|step|ret`

Introspection:
- `GET  /modules`
- `GET  /modules/<name>/exports` — forwarded entries appear as `name=Foo forward=other.dll.RealName`
- `GET  /threads` — per-thread DR state, `accessible`, `agent` flag, `attach_ok`/`attach_fail` counters
- `GET  /symbols/resolve?name=module!symbol` (uses `GetProcAddress` so forwards follow)
- `GET  /symbols/lookup?addr=0x...` — address → `module+0xoffset`

Misc:
- `GET  /ping` `GET /version` `POST /shutdown`
- `GET  /info` — `version=...\narch=x86_64|x86\npid=...\nuptime_ms=...`

## License

AGPL-3.0. See [LICENSE](LICENSE).

For closed-source / SaaS use without publishing modifications, open
an issue.
