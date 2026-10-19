# Security

The Pit's protection rests entirely on keys only you hold. The design is public, the code is open,
and nothing depends on it being secret how The Pit works (Kerckhoffs's principle).

## Keys, and the ways in

A random 256-bit **vault key** encrypts everything. It is never stored as is. Instead it is wrapped
once per **slot**, and any one slot opens the vault:

| Slot | Unwrapped by | Used for |
| --- | --- | --- |
| password | Argon2id(your password) | every day |
| recovery | your recovery code (256 random bits) | forgotten password; also resets factors |
| device | a random key in the macOS Keychain, which the agent uses only after Touch ID confirms you | quick unlock |

On top of the slots, a **second factor** is enforced after the password: Touch ID, or an RFC 6238
authenticator code. Quick unlock (Touch ID alone) is only accepted if the password itself was used
within the last 7 days (`pit settings password_recheck_days`).

From the vault key, independent keys are derived (HKDF-SHA256) for the library, for individual
secret values, for the audit log and for fingerprints. Secret values are encrypted a second time,
individually, bound to their identity — they stay ciphertext in memory until a push or reveal
needs one, and a value cannot be swapped onto another secret undetected.

Every identity also gets an **X25519 key pair**, so bundles can be encrypted to a specific person.

## What is used, and why

| Concern | Standard |
| --- | --- |
| Password-based keys | Argon2id, RFC 9106 — 128 MiB, 3 passes, 4 lanes (above OWASP's minimum) |
| Encryption | XChaCha20-Poly1305 (RFC 8439, extended nonce) — authenticated; random 192-bit nonces |
| Key separation | HKDF-SHA256, RFC 5869 |
| Fingerprints | HMAC-SHA256 under a vault-derived key — cannot be used to test guesses outside the vault |
| One-way secrets | Argon2id hash with per-secret salt; verified in constant time |
| Second factor | RFC 6238 TOTP (replay-protected), and Apple LocalAuthentication (Touch ID / Watch) |
| Recovery splitting | Shamir secret sharing over GF(2⁸), constant-time arithmetic |
| Recovery codes | Crockford base32 with a checksum, so typos are caught before any key is derived |
| GitHub secrets | libsodium sealed boxes (X25519 + XSalsa20-Poly1305), as GitHub requires |
| Transport | HTTPS only (rustls, Mozilla roots), no redirects; local IPC over a Unix socket |
| Passwords | NIST SP 800-63B: length over composition rules; screened for guessability (zxcvbn); ≥ 12 characters and ≥ 10¹² estimated guesses |
| Implementations | RustCrypto crates (`argon2`, `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `crypto_box`) — no hand-rolled primitives |

## How the running system is protected

- **One process holds keys.** The agent. CLI, console and MCP clients never see the vault key.
- **Owner-only everything.** `~/.the-pit` and every directory in it are `0700`, every file `0600`,
  created with a `0077` umask. The agent's socket is `0600` in a `0700` directory, and the agent checks
  the connecting process's user id on every connection.
- **No core dumps**, and in release builds the agent refuses debugger attachment.
- **Keys are wiped** from memory when the session ends (zeroize on drop). Sessions end at a maximum
  age, after idle time, or on `pit lock`.
- **Throttling.** After 3 wrong passwords or codes — at unlock or at an approval — each further attempt
  waits exponentially longer (up to an hour), and 6 wrong approvals close the session. The count
  survives restarts and is kept in more than one place, so clearing one does not reset it.
- **One approval per batch of changes.** After you approve a change, further changes to the same
  channel (or project) from the same terminal tab — or the same app — go ahead without asking for 5
  minutes, so editing 20 secrets and pushing them asks once. The window is tied to that terminal's
  process and its start time, so other tabs, other apps and AI clients are still asked. Reveals,
  `pit run`, removals, exports and settings are asked about every time. Each window is in `pit log`
  (`approval.window`); `pit settings approval_window_secs 0` turns it off. Push previews (dry runs)
  send nothing and never ask.
- **Destinations need approval.** Adding or changing a destination — where values get sent — always
  asks for your approval, on any channel.
- **No log entry, no value.** Reveals, `pit run`, exports and pushes are refused if their audit entry
  cannot be written; a push is logged before anything is sent.
- **No secret on a command line, in a URL or in a log.** Values travel over standard input or request
  bodies; passwords are read from the terminal with echo off.
- **Atomic writes.** Every file is written to a temporary file, flushed, and renamed. The last 30
  versions of the library are kept (encrypted) for `pit history`.
- **Tamper-evident audit log.** Every entry is encrypted and chained to the previous one by SHA-256,
  and a sealed anchor plus a counter inside the library record the newest entry. `pit log` verifies
  the chain and reports the first altered, removed or cut-off entry.
- **No silent rollback.** The newest library generation is recorded in the Keychain, outside the vault
  folder; an older library file swapped in is refused (a deliberate `pit backup restore` resets it).
- **Bundles are untrusted input.** Imported names are validated, and a bundle's destinations and
  connections — where secrets get pushed — are only taken with `--with-destinations`.
- **AI clients get no values.** The MCP server has no tool that returns one, and the agent refuses
  value-returning operations from clients that identify as MCP. Their pushes wait for your Touch ID
  or `pit approve`. An AI that can also run shell commands could run `pit` like any other program —
  and then meets the same wall as any program: reveals, `pit run`, exports and protected pushes need
  your Touch ID, code or password. Approval tickets are single-use and bound to the exact request.
- **Clipboard** copies (`pit reveal --copy`) are cleared after 30 seconds if still on the clipboard.
- **Destinations are guarded**: paths are resolved (symlinks and `..`) before checking; no writing into
  The Pit's folder or through a symlink, no un-ignored files in git repositories,
  no unprotected channel writing to a protected channel's address, no Vercel production target from an
  unprotected channel. Destination settings can only be filled from `plain` secrets, so a sealed value
  never ends up in an address, a log line or an AI client's view.

## Malicious code running as you

A poisoned dependency (`npm i`, a `postinstall` script, an editor task) runs with your user's
permissions. The Pit is built so that is not enough:

- **There are no plaintext secret files to read.** The vault is ciphertext; it opens only inside the
  agent, with your keys.
- **Secrets stay out of shell environments.** Keep nothing in `~/.zshenv` or `~/.zshrc`; use
  `pit run -c myapp/development -- <command>` so a value exists only in the one program that needs it,
  for as long as it runs. A script that dumps `process.env` in another terminal finds nothing.
- **Handing values to a program needs you.** `pit run`, `pit reveal`, exports, and any push to a
  protected channel ask for Touch ID (or your code/password). Malware can call `pit` too; it cannot
  touch the sensor. `pit elevate --for 30m` opens a window for a working session if the taps get in
  the way — but while it is open, the approvals it covers are open to any program running as you, so
  keep it short and only use it when you are actively working, and `pit settings run_needs_approval false` turns this off for `pit run` if you accept that trade.
- **Every request is logged with the program that made it** (and its parent), so an unexpected caller
  shows up in `pit log`.

## What The Pit does not protect against

Be clear-eyed about these, as with any local vault:

- Software running as you while the pit is **unlocked** can ask the agent for what an unlocked session
  allows without approval: listing names, and pushing unprotected channels to the destinations you
  already approved (which re-writes files that already exist there). Keep sessions short
  (`pit settings idle_secs 15m`), lock when you step away, and protect channels whose secrets matter.
- Once a secret is pushed to a service or rendered into a `.env` file, its safety there is that
  service's or that file's.

## If you lose access

Every way back in, from most to least common:

| You still have | Do this |
| --- | --- |
| Your password, not your second factor (lost phone, no Touch ID) | `pit recover` with your recovery code, then `pit mfa totp` (or `pit mfa touchid on`) to enroll again. |
| Your recovery code (forgot the password) | `pit recover` — opens the vault and makes you set a new password. Factors can then be reset. |
| Enough recovery **shares** (if you split the code) | `pit recover`, paste the shares separated by commas. |
| A snapshot backup **and** the password or recovery code from when it was taken | `pit backup restore FILE`, then unlock. |
| A passphrase bundle or emergency export, and its passphrase | `pit init` a new vault, then `pit backup import FILE --passphrase`. |
| Your password, but you want **out** | `pit emergency export --out everything.pitbundle` (encrypted with a passphrase you choose), or `--plaintext --out DIR` to dump every secret as files. Then `pit emergency destroy`. |
| Nothing at all | The secrets cannot be recovered by anyone — that is the guarantee. You can still remove the vault: `pit emergency destroy` needs no key. Then rotate the credentials at each service. |

Prepare now so the last row never applies:

1. Keep the recovery code off this computer. Better: split it — `pit recovery rotate --split 2-of-3` —
   and keep the shares in three different places.
2. Enroll an authenticator app (`pit mfa totp`) as well as Touch ID.
3. Send snapshots somewhere else (`pit backup target …`). Every change is sent automatically; `pit backup status` shows any target that is behind.
4. Once a year, make an encrypted export (`pit emergency export --out …`) and store it with your recovery code.

## Reporting a vulnerability

Please report privately to the maintainer rather than in a public issue.
