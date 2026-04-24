# haunt

A minimal debugger-as-an-HTTP-server. Inject `haunt.dll` into a target
Windows process, drive it from anywhere with `curl` or the `haunt` CLI.

Memory read/write, software/hardware/page breakpoints, halt with register
snapshot, resume/step/run-to-return — over a flat REST surface with no
runtime dependencies on the target.

## Layout

```
crates/
├── core/      haunt-core      platform-agnostic HTTP + protocol
├── windows/   haunt-windows   cdylib → haunt.dll
├── inject/    haunt-inject    CreateRemoteThread(LoadLibraryA)
└── cli/       haunt           haunt.exe
```

## Build

Requires Rust (`rustup`) and MinGW-w64 on macOS / Linux for cross-compile.

```sh
# macOS
brew install mingw-w64

# build everything for Windows x86_64
./build.sh           # haunt.dll only
cargo build --release   # all artifacts
```

Output ends up in `target/x86_64-pc-windows-gnu/release/`:

- `haunt.dll` — the agent (~400 KB, system DLLs only, no MinGW runtime deps)
- `haunt-inject.exe` — loader
- `haunt.exe` — CLI client

## Quick start

On the Windows target, with all three binaries colocated:

```sh
haunt-inject --pid 1234 .\haunt.dll

# same box, talk to the agent
set HAUNT_URL=http://127.0.0.1:7878
haunt ping
haunt modules
haunt exports kernel32.dll
haunt bp set 0x7FF601234000 --kind sw
haunt wait          # long-polls until a breakpoint halts a thread
haunt regs 1        # hit_id
haunt resume 1 --step
```

## Workflows

End-to-end recipes that stitch the primitives together. All commands
assume `HAUNT_URL` is set and the agent is running in the target.

**Trace a function call and inspect arguments.** Set a breakpoint on
entry, wait for it to hit, read the register snapshot, then let it
continue.

```sh
haunt exports kernel32.dll | grep CreateFileW
haunt bp set 0x7FFD12340000 --kind sw
haunt wait                              # blocks until a thread halts
haunt regs 3                            # hit_id from wait output; args in rcx/rdx/r8/r9
haunt read 0x00000014FE3C0000 64        # dereference a pointer arg
haunt resume 3
```

**Patch a return value without touching code.** Halt at the `ret`,
overwrite `rax`, resume.

```sh
haunt bp set 0x7FF601234ABC --kind sw --one-shot
haunt wait
printf 'rax=0\n' | haunt setregs 7
haunt resume 7
```

**Watch a field for writes.** Hardware breakpoint with `--access w`
catches any thread modifying the address; breakpoints auto-propagate to
new threads.

```sh
haunt bp set 0x00007FF6DEADBEEF --kind hw --access w --size 4
haunt wait --timeout 60000
haunt regs 12                           # rip points at the writing instruction
haunt resume 12
```

**Non-halting tripwire.** `--no-halt` records hits without parking the
thread — useful for sampling hot paths.

```sh
haunt bp set 0x7FF601234000 --kind sw --no-halt
# ...let it run...
haunt bp list                           # hit counts per breakpoint
```

## Protocol

All endpoints are plain HTTP/1.1. Auth is opt-in via `HAUNT_TOKEN`
(`Authorization: Bearer <token>`). Bind defaults to `127.0.0.1:7878`.

Memory:
- `GET  /memory/read?addr=0x...&len=N[&format=hex|raw]`
- `POST /memory/write?addr=0x...`  (raw body)
- `GET  /memory/regions`

Breakpoints:
- `POST /bp/set?addr=0x...&kind=sw|hw|page[&access=x|w|rw|any][&size=N][&halt=true|false][&one_shot=true][&tid=N]`
- `POST /bp/clear?id=N`
- `GET  /bp/list`

Halts (parked threads):
- `GET  /halts`
- `GET  /halts/wait?timeout=<ms>`
- `GET  /halts/<hit_id>`                       — register dump
- `POST /halts/<hit_id>/regs`                  — modify registers
- `POST /halts/<hit_id>/resume?mode=continue|step|ret`

Introspection:
- `GET  /modules`
- `GET  /modules/<name>/exports`
- `GET  /memory/regions`
- `GET  /ping`  `GET  /version`  `POST /shutdown`

## Status

- x86_64 Windows only for now. The `Process` trait is platform-agnostic;
  a Linux implementation is on the roadmap.
- Breakpoint kinds: software (`int3`), hardware (DR0–DR3), page
  (PAGE_GUARD).
- Hardware breakpoints propagate to new threads via `DLL_THREAD_ATTACH`
  (uses `SetThreadContext` on self — documented-fragile but empirically
  reliable on modern Windows).
- `panic = "abort"`; the agent is audited for unwrap/expect. Memory
  read/write uses `ReadProcessMemory`/`WriteProcessMemory` so invalid
  addresses surface as errors rather than crashing the host.

## License

AGPL-3.0. See [LICENSE](LICENSE).

If you want to use haunt in a closed-source or SaaS product without
publishing your modifications, you'll need a different arrangement —
open an issue.
