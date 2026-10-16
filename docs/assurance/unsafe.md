# `unsafe` code review

Rust's memory-safety guarantees cover everything except code marked `unsafe`. The Pit uses
`unsafe` only to call operating-system functions (through `libc` and Apple's frameworks) that
have no safe Rust wrapper. There is no `unsafe` in the cryptography, the parsers or the vault
format: those use the RustCrypto crates and safe Rust only.

Reviewed: 2026-10-15, version 0.1.0. CI's Semgrep job skips its generic "unsafe used" rule
because every use is listed and reviewed here; a new `unsafe` block should be added to this
table in the same pull request.

| Where | Call | Why it is sound |
|---|---|---|
| `harden.rs` `process` | `umask`, `setrlimit(RLIMIT_CORE, 0)` | Plain integer arguments and a stack `rlimit`; no pointers kept. |
| `harden.rs` `agent` | `ptrace(PT_DENY_ATTACH)` (macOS release), `prctl(PR_SET_DUMPABLE, 0)` (Linux) | Integer arguments, null pointer where the API expects none. |
| `harden.rs` `peer` (Linux) | `getsockopt(SO_PEERCRED)` | Writes into a correctly sized, initialised `ucred` on the stack; length passed and checked by the kernel; result ignored on error. |
| `harden.rs` `peer` (macOS/BSD) | `getpeereid`, `getsockopt(LOCAL_PEERPID)` | Out-parameters are initialised stack integers of the exact type; errors handled. |
| `harden.rs` `process_path` | `proc_pidpath` | Buffer pointer and its true length are passed; only the returned `n ≤ len` bytes are read. |
| `harden.rs` `parent_pid` | `proc_pidinfo(PROC_PIDTBSDINFO)` | Zeroed `proc_bsdinfo` (plain C struct, all-zero is valid); used only if the kernel filled exactly its size. |
| `agent.rs`, `paths.rs` ×4, `service.rs` | `getuid` | No arguments; cannot fail. |
| `backup.rs` `SyncLock` | `flock(LOCK_EX / LOCK_UN)` | File descriptor owned by a live `File` for the lock's whole lifetime. |
| `cli.rs` `run` | `signal(SIGINT/TERM/HUP/QUIT, handler)` | The handler is an empty `extern "C" fn` — async-signal-safe by construction. |
| `protocol.rs` `ensure_agent` | `pre_exec(setsid)` | Runs between `fork` and `exec`; `setsid` is async-signal-safe and allocates nothing. |
| `presence.rs` ×2 | `LAContext` (LocalAuthentication / Touch ID) via `objc2` | Objective-C message sends with owned, retained objects; the reply block only sends a `bool` on a channel and is kept alive until the reply or a 90 s timeout. |

## Tooling

- **Semgrep** (`p/rust`) reports each `unsafe` block; they are excluded in CI because of this review.
- **Miri** cannot run these calls (they are foreign functions), so this review stands in for it.
- The fuzz targets (`fuzz/`) run with AddressSanitizer on Linux in CI, which would catch memory errors
  in any code they reach.
