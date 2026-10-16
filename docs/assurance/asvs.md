# OWASP ASVS 5.0 self-assessment

| | |
| --- | --- |
| Date | 2026-10-15 |
| Version assessed | 0.1.1 (2026-10-15). |
| Standard | OWASP Application Security Verification Standard 5.0.0, Level 3 |
| Kind | **Self-assessment by the maintainer. This is not an independent audit**, and it is not a certification. |

## Scope and method

**What The Pit is.** A local secrets vault: a `pit` command-line program, an interactive console, an
MCP server for AI clients, and one background agent that holds the keys and listens on an owner-only
Unix socket. It talks outward only to the services it pushes to (Fly, Vercel, GitHub) and to backup
targets (folders, SSH, rclone, S3). It has no web interface, no browser code, no user accounts beyond
the one owner, no HTTP server and no database. Many ASVS requirements are written for web applications,
so they are marked not applicable (N/A) with a reason.

**Source of the requirements.** Every requirement ID and its meaning come from the official ASVS 5.0.0
export in the OWASP repository: `5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`
on <https://github.com/OWASP/ASVS> (346 requirements in 17 chapters). The "Requirement" column below is a
short summary of each requirement; the full wording is in that file. Algorithm status (approved / legacy)
follows ASVS 5.0 Appendix C.

**How it was assessed.**

1. Read the design documents: `README.md`, `SECURITY.md`, `docs/security.md`, `docs/concepts.md`,
   `docs/backups.md`, `docs/integrations.md`, `docs/commands.md`.
2. Read the code that implements each control and checked that the documents match it: `src/crypto.rs`,
   `src/vault.rs`, `src/values.rs`, `src/agent.rs`, `src/ops.rs`, `src/harden.rs`, `src/paths.rs`,
   `src/audit.rs`, `src/totp.rs`, `src/codes.rs`, `src/shamir.rs`, `src/presence.rs`, `src/keychain.rs`,
   `src/protocol.rs`, `src/mcp.rs`, `src/backup.rs`, `src/s3.rs`, `src/model.rs`, `src/cli.rs`,
   `src/rail/`, `src/lib.rs`, `Cargo.toml`, `Cargo.lock`, `deny.toml`, `.github/dependabot.yml`,
   `.github/workflows/` (`ci.yml`, `security.yml`, `codeql.yml`, `scorecard.yml`, `assurance.yml`,
   `release.yml`), `fuzz/`, `tests/crypto_vectors.rs`, `tests/security_core.rs` and
   `docs/assurance/unsafe.md`.
3. Assessed every requirement (all levels, L1 to L3) in the chapters that apply to a local vault.
   Chapters that are entirely about browsers or web protocols are listed once under
   [Not applicable chapters](#not-applicable-chapters).
4. Where code and documents disagreed, the code decided the status.

No vault, key store entry or secret value was read for this assessment; only the repository.

**Status meanings.**

| Status | Meaning |
| --- | --- |
| Met | The code does what the requirement asks, at Level 3. |
| Partly met | Some of it is done; the row says what is missing and what would close it. |
| Not met | Not done. The row says what would close it. |
| N/A | Does not apply to a local, single-owner CLI vault; the row says why. |

## Summary

Counts cover the 243 requirements in the twelve assessed chapters. The five web-only chapters
(103 requirements) are listed separately.

| Chapter | Met | Partly met | Not met | N/A | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| V1 Encoding and Sanitization | 16 | 1 | 0 | 13 | 30 |
| V2 Validation and Business Logic | 8 | 3 | 0 | 2 | 13 |
| V5 File Handling | 3 | 2 | 0 | 8 | 13 |
| V6 Authentication | 27 | 9 | 0 | 11 | 47 |
| V7 Session Management | 8 | 3 | 0 | 8 | 19 |
| V8 Authorization | 8 | 4 | 0 | 1 | 13 |
| V11 Cryptography | 15 | 5 | 3 | 1 | 24 |
| V12 Secure Communication | 5 | 1 | 2 | 4 | 12 |
| V13 Configuration | 9 | 7 | 1 | 4 | 21 |
| V14 Data Protection | 6 | 2 | 0 | 5 | 13 |
| V15 Secure Coding and Architecture | 13 | 4 | 1 | 3 | 21 |
| V16 Security Logging and Error Handling | 9 | 8 | 0 | 0 | 17 |
| **Total** | **127** | **49** | **7** | **60** | **243** |

## Not applicable chapters

| Chapter | Requirements | Why it does not apply |
| --- | ---: | --- |
| V3 Web Frontend Security | 31 | No browser-facing content: no HTML, cookies, CSP, CORS or JavaScript. |
| V4 API and Web Service | 16 | No HTTP, REST, GraphQL or WebSocket service. The agent speaks line-delimited JSON over a local Unix socket (assessed under V8, V12 and V15). |
| V9 Self-contained Tokens | 7 | No JWTs or other self-contained tokens are issued or accepted. |
| V10 OAuth and OIDC | 36 | Not an OAuth client, resource server or authorization server. Service access uses tokens the owner creates at the service (`pit connect`). |
| V17 WebRTC | 12 | No real-time media. |

---

## V1 Encoding and Sanitization

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V1.1.1 | 2 | Decode input to canonical form once, before validation | Met | Each request is parsed once by `serde_json` in `agent.rs` `serve`; base64 fields are decoded once in `ops.rs` via `crypto::b64d`. |
| V1.1.2 | 2 | Encode output as the last step, for the interpreter that uses it | Met | `.env` values are quoted when rendered (`rail/local.rs` `quote`, `render`); JSON is built by `serde_json`; paths in remote SSH commands are quoted with `shell_words::quote` (`backup.rs`). |
| V1.2.1 | 1 | Context-aware output encoding for HTTP/HTML/XML | N/A | No HTML, XML or HTTP responses are produced. |
| V1.2.2 | 1 | Encode untrusted data when building URLs; safe URL schemes only | Met | Path parts are URL-encoded (`rail/github.rs`, `rail/vercel.rs` `urlencode`, `s3.rs` `encode_path`); only `https://` is accepted (`rail/http.rs` `https_only`, `s3.rs` `location`). |
| V1.2.3 | 1 | Encode when building JavaScript/JSON | Met | All JSON is produced with `serde_json` (`json!`), never by string concatenation (`mcp.rs`, `protocol.rs`, `ops.rs`). |
| V1.2.4 | 1 | Parameterized database queries | N/A | No database. |
| V1.2.5 | 1 | Protect against OS command injection | Met | External programs are started with argument vectors, no shell (`rail/command.rs` `push`, `rail/fly.rs`, `backup.rs` `ssh`, `rclone`, `send`); the one remote shell command string quotes every path (`backup.rs`). |
| V1.2.6 | 2 | LDAP injection | N/A | No LDAP. |
| V1.2.7 | 2 | XPath injection | N/A | No XPath. |
| V1.2.8 | 2 | LaTeX injection | N/A | No LaTeX. |
| V1.2.9 | 2 | Escape special characters in regular expressions | Met | All regular expressions are fixed patterns in `scan.rs`; no input is compiled into a pattern. |
| V1.2.10 | 3 | CSV and formula injection | N/A | No CSV or spreadsheet export. |
| V1.3.1 | 1 | Sanitize WYSIWYG HTML | N/A | No HTML input. |
| V1.3.2 | 1 | No `eval()` or dynamic code execution | Met | Rust; no interpreter or expression language is embedded. |
| V1.3.3 | 2 | Sanitize data passed to dangerous contexts | Met | Names are allow-listed (`model.rs` `valid_name`, `valid_slug`, `safe_relative`); values are quoted for `.env` output (`rail/local.rs`). |
| V1.3.4 | 2 | Sanitize user-supplied SVG | N/A | No SVG handling. |
| V1.3.5 | 2 | Sanitize scriptable/template content (Markdown, CSS, XSL) | N/A | No such content is rendered. |
| V1.3.6 | 2 | Protect against SSRF with allow-lists | Met | Outbound requests go only to fixed service hosts (`rail/github.rs` `API`, `rail/vercel.rs`) or to HTTPS endpoints the owner configured (`s3.rs`); redirects are off (`rail/http.rs`). Adding or changing any destination always needs the owner's approval (`ops.rs` `needs_approval`). |
| V1.3.7 | 2 | Prevent template injection | Met | No template engine; destination settings may reference only `plain` secrets as `{NAME}` (`ops.rs` `template_value`). |
| V1.3.8 | 2 | JNDI injection | N/A | No JNDI. |
| V1.3.9 | 2 | Memcache injection | N/A | No memcache. |
| V1.3.10 | 2 | Sanitize format strings | Met | Rust format strings are fixed at compile time. |
| V1.3.11 | 2 | SMTP/IMAP injection | N/A | No mail. |
| V1.3.12 | 3 | Regular expressions free of exponential backtracking | Met | The Rust `regex` crate matches in linear time; `scan.rs` also caps file size (1 MiB), file count and depth. |
| V1.4.1 | 2 | Memory-safe strings and copies | Met | Rust. `unsafe` is limited to OS calls, and every block is listed and reviewed in `docs/assurance/unsafe.md`. Six fuzz targets run with AddressSanitizer in CI (`fuzz/fuzz_targets/`, `.github/workflows/assurance.yml`). |
| V1.4.2 | 2 | Prevent integer overflow | Met | `overflow-checks = true` in the release profile (`Cargo.toml`); timers use saturating arithmetic. |
| V1.4.3 | 2 | Release memory; no dangling pointers | Met | Rust ownership rules. |
| V1.5.1 | 1 | Restrictive XML parser configuration | N/A | No XML. |
| V1.5.2 | 2 | Safe deserialization of untrusted data | Met | Data is deserialized only into fixed `serde` types; bundles and snapshots are checked before use (`backup.rs` `inspect_snapshot`, `check_imported_secret`). Agent requests, snapshots, imports, sealed records, recovery codes and TOTP input are fuzzed (`fuzz/fuzz_targets/`). |
| V1.5.3 | 3 | Parsers for the same data type behave consistently | Partly met | One JSON parser (`serde_json`) everywhere, but `.env` text is parsed by two separate functions (`rail/local.rs` `parse_dotenv`, `importer.rs` `parse_env`) and YAML by a hand-written reader (`scan.rs` `read_yaml`). **Close:** use one shared `.env` parser, and test that all readers agree on the same inputs. |

## V2 Validation and Business Logic

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V2.1.1 | 1 | Document input validation rules | Met | `docs/concepts.md` (names: letters, digits, `_ - . @ /`; scopes; selectors); enforced in `model.rs` `valid_name`. |
| V2.1.2 | 2 | Document rules for combined data items | Met | `docs/concepts.md` and `docs/security.md`: an unprotected channel cannot target a protected channel's address; one-way secrets cannot be pushed. |
| V2.1.3 | 2 | Document business logic limits | Partly met | Some limits are documented (session times, kept history), others only exist in code (generated value length 16–4096, setting ranges, up to 16 recovery shares, name lengths). **Close:** list every limit in `docs/`. |
| V2.2.1 | 1 | Validate all input against allow-lists, structures and ranges | Met | `model.rs` `valid_name`, `valid_slug`, `safe_relative`; settings are clamped (`ops.rs` `settings.set`); recovery share counts are range-checked (`ops.rs` `recovery.rotate`). |
| V2.2.2 | 1 | Enforce validation at a trusted service layer | Met | All checks run in the agent (`ops.rs` `dispatch`, `needs_approval`), not in the CLI. |
| V2.2.3 | 2 | Check that combinations of related items are reasonable | Met | `ops.rs` `guard_collisions` (address reuse across channels), `guard_one_way` (one-way secrets that a destination would push). |
| V2.3.1 | 1 | Process flows in order without skipping steps | Met | Unlock is password, then second factor (`agent.rs` `unlock`, `second_factor`); approvals are tickets bound to the exact request (`agent.rs` `gate`, `digest`). After a recovery unlock, the new-password step is prompted by the CLI (`cli.rs` `recover`). |
| V2.3.2 | 2 | Implement documented business logic limits | Met | Limits above are enforced in `ops.rs` and `model.rs`. |
| V2.3.3 | 2 | Operations succeed fully or roll back | Met | A failed operation restores the in-memory library (`agent.rs` `handle`); files are written atomically (`paths.rs` `write_private`). |
| V2.3.4 | 2 | Locking for limited-quantity resources | N/A | No limited-quantity resources. Agent state is behind one mutex (`agent.rs` `Shared`). |
| V2.3.5 | 3 | Multi-user approval for high-value flows | N/A | A vault has exactly one owner. (Recovery can optionally be split K-of-N with `pit recovery rotate --split`.) |
| V2.4.1 | 2 | Anti-automation against excessive calls | Partly met | Guesses at passwords, codes and approvals are throttled with persistent back-off (`agent.rs` `throttle_check`, `throttle_fail`). Routine calls in an unlocked session and the number of pending approval requests are not limited. **Close:** a per-client rate limit and a cap on pending approvals. |
| V2.4.2 | 3 | Require realistic human timing | Partly met | Sensitive actions need a person (Touch ID, code or password) through `agent.rs` `gate`; routine actions have no timing check. **Close:** as V2.4.1. |

## V5 File Handling

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V5.1.1 | 2 | Document permitted file types and maximum sizes | Partly met | Accepted inputs are documented (`docs/importing.md`: `.env`/JSON/YAML; `docs/backups.md`: bundles and snapshots; `docs/concepts.md`: file secrets). The 64 MiB request limit exists in code (`agent.rs` `MAX_REQUEST`) but is not documented. **Close:** document the maximum sizes. |
| V5.2.1 | 1 | Accept only file sizes the application can process | Partly met | Every request to the agent is capped at 64 MiB (`agent.rs` `MAX_REQUEST`), which bounds file secrets, imports and bundles sent to it; `scan.rs` caps file size (1 MiB), count and depth. Files the CLI reads directly, such as a snapshot being restored (`cli.rs`, `backup.rs` `restore_snapshot`), have no limit. **Close:** a size limit for files read directly by the CLI. |
| V5.2.2 | 1 | Check extension and content type of accepted files | Met | Imports are parsed by strict format readers and rejected otherwise; bundles and snapshots carry a format tag and are authenticated (AEAD) or checksummed (`backup.rs` `inspect_snapshot`). File secrets are stored as opaque bytes and never interpreted or executed. |
| V5.2.3 | 2 | Check compressed files before decompressing | N/A | No archive handling. |
| V5.2.4 | 3 | Per-user file size and count quotas | N/A | One owner, storing on their own disk. |
| V5.2.5 | 3 | No symlinks inside uploaded archives | N/A | No archives. (Local destinations refuse to write through a symlink: `rail/local.rs` `guard_location`.) |
| V5.2.6 | 3 | Reject oversized images | N/A | No image handling. |
| V5.3.1 | 1 | Uploaded files in public folders not executed | N/A | No web serving. |
| V5.3.2 | 1 | Use trusted data for file paths; validate user file names | Met | Snapshot restore accepts only a fixed list of file names (`backup.rs` `inspect_snapshot`, `SNAPSHOT_FILES`); file-secret names must be plain relative paths (`model.rs` `safe_relative`, `rail/local.rs` `safe_join`); destination paths are resolved and checked before writing (`rail/local.rs` `guard_location`). |
| V5.3.3 | 3 | Ignore user path information in decompression | Met | Snapshots with any unexpected path are refused (`backup.rs` `inspect_snapshot`); there is no other unpacking. |
| V5.4.1 | 2 | Validate file names in downloads; set Content-Disposition | N/A | No HTTP downloads. |
| V5.4.2 | 2 | Encode served file names | N/A | No files are served. |
| V5.4.3 | 2 | Antivirus scan of files from untrusted sources | N/A | Files are not served to others; imported data is parsed, never executed. |

## V6 Authentication

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V6.1.1 | 1 | Document rate limiting and anti-automation for authentication | Met | `docs/security.md` "Throttling"; `agent.rs` `throttle_check` (back-off up to one hour). |
| V6.1.2 | 2 | Document context-specific words banned from passwords | Partly met | The code passes the owner's name and product words to the strength check (`cli.rs` `password_policy`), but the list is not documented. **Close:** document the list. |
| V6.1.3 | 2 | Document all authentication pathways and their strength | Met | `docs/security.md` "Keys, and the ways in" (password, recovery code, quick unlock, second factor) and "If you lose access". |
| V6.2.1 | 1 | Passwords at least 8 characters (15 recommended) | Met | At least 12 characters plus an estimated 10¹² guesses (`cli.rs` `password_policy`). |
| V6.2.2 | 1 | Users can change their password | Met | `pit password` (`cli.rs` `Cmd::Password`, `ops.rs` `password.change`). |
| V6.2.3 | 1 | Password change requires current and new password | Partly met | The CLI sends the current password and `agent.rs` `gate` verifies it, but an open `pit elevate` window lets the gate pass without it. **Close:** require the current password (or a recovery unlock in the same session) for `password.change`, whatever the elevation state. |
| V6.2.4 | 1 | Check new passwords against at least the top 3000 passwords | Met | `zxcvbn` (common-password dictionaries) with a 10¹² guess threshold (`cli.rs` `password_policy`). |
| V6.2.5 | 1 | No composition rules | Met | Length and estimated strength only. |
| V6.2.6 | 1 | Password entry is masked | Met | Terminal echo is off (`cli.rs` `prompt_hidden`, `rpassword`). |
| V6.2.7 | 1 | Paste and password managers allowed | Met | Terminal paste is accepted; nothing blocks it. |
| V6.2.8 | 1 | Password verified exactly as entered | Met | Bytes go unchanged to Argon2id (`vault.rs` `Header::unwrap`). |
| V6.2.9 | 2 | Passwords of 64+ characters permitted | Met | Up to 1024 characters (`cli.rs` `password_policy`). |
| V6.2.10 | 2 | No periodic password rotation | Met | No expiry. `password_recheck_days` only asks that the password be *used* within a period before quick unlock, not changed. |
| V6.2.11 | 2 | Context-specific word list is used | Met | `cli.rs` `password_policy` (owner name, "the pit", "pit", "secret", "password"). |
| V6.2.12 | 2 | Check passwords against breached-password sets | Partly met | Offline `zxcvbn` dictionaries only; no breached-password corpus. **Close:** an offline breached-password filter shipped with the binary, or an opt-in range query. |
| V6.3.1 | 1 | Controls against brute force, as documented | Met | Persistent exponential back-off shared by unlock and approvals; the count is kept in a file, the OS keychain and the agent's memory, and the highest wins (`agent.rs` `throttle_load`, `throttle_fail`); Argon2id at 128 MiB per guess (`crypto.rs` `KdfParams::new_password`). |
| V6.3.2 | 1 | No default accounts | Met | No accounts; the owner creates the only credential at `pit init`. |
| V6.3.3 | 2 | Multi-factor required; L3: one factor hardware-based and phishing-resistant | Partly met | When enrolled, a second factor (Touch ID or TOTP) is enforced after the password (`agent.rs` `second_factor`). Enrolment is optional, so a password-only vault is possible; and Touch ID is a local LocalAuthentication check (`presence.rs`), not a key-bound hardware authenticator. **Close:** require a second factor at `pit init`; bind the quick-unlock key to Secure Enclave biometric access control; consider a FIDO2 security key as a key slot. |
| V6.3.4 | 2 | No undocumented pathways; consistent strength | Met | The pathways in `agent.rs` `unlock` (password, recovery, touchid) and `gate` (elevation, ticket, code, password, Touch ID) match `docs/security.md` and `docs/concepts.md`. |
| V6.3.5 | 3 | Notify users of suspicious authentication attempts | Partly met | The number of failed attempts is recorded in the next `unlock` audit entry (`agent.rs` `unlock`, `failed_attempts_before`) but not shown to the person. **Close:** show failed attempts since the last unlock, and when quick unlock or recovery was last used, at every unlock. |
| V6.3.6 | 3 | Email not used for authentication | Met | No email. |
| V6.3.7 | 3 | Notify after authentication details change | Partly met | Changes to password, factors, quick unlock and recovery code are audit-logged (`ops.rs` `password.change`, `mfa.*`, `device.set`, `recovery.rotate`) and confirmed on screen, but not raised again later. **Close:** at the next unlock, list authentication changes made since the previous one. |
| V6.3.8 | 3 | Valid users cannot be deduced | N/A | One owner, no user identifiers. Failed unlocks return the same `access denied` (`error.rs` `Error::Denied`). |
| V6.4.1 | 1 | System-generated initial passwords are random and expire | N/A | No initial passwords. The recovery code is a separate 256-bit key slot (`vault.rs` `new_recovery`). |
| V6.4.2 | 1 | No password hints or secret questions | Met | None exist. |
| V6.4.3 | 2 | Password reset does not bypass enabled MFA | Partly met | Recovery (256-bit code or K-of-N shares) opens the vault and allows a new password without the enrolled second factor. This is a deliberate, documented design (`docs/security.md` "If you lose access"; comment in `agent.rs` `unlock`) so a lost phone does not lock the owner out. **Close:** either require an enrolled factor with recovery unless the owner declares it lost, or record this as a formal deviation with its rationale. |
| V6.4.4 | 2 | Identity proofing for lost factors at enrolment level | Met | A lost factor is replaced only from a session opened with the recovery code (stronger than enrolment) or an approved session (`ops.rs` `ALWAYS_APPROVE` for `mfa.*`). |
| V6.4.5 | 3 | Renewal reminders before authenticators expire | N/A | No authenticator expires. |
| V6.4.6 | 3 | Admins can start but not choose a user's reset | N/A | No administrators. |
| V6.5.1 | 2 | OTPs and lookup secrets usable once | Met | TOTP steps at or before the last used one are rejected and the step is persisted (`totp.rs` `verify`, `agent.rs`); approval tickets are removed on use (`agent.rs` `gate`). |
| V6.5.2 | 2 | Low-entropy lookup secrets stored hashed | Met | The recovery code is never stored; it derives a wrapping key (`vault.rs` `Unlocker::Recovery`). It has 256 bits. |
| V6.5.3 | 2 | OTP seeds and codes from a CSPRNG | Met | `totp.rs` `new_secret` (160 bits from the OS random source); recovery key from `crypto.rs` `random_bytes`. |
| V6.5.4 | 2 | Lookup secrets have at least 20 bits of entropy | Met | Recovery code: 256 bits. |
| V6.5.5 | 2 | Defined lifetimes; TOTP at most 30 seconds | Partly met | Approval tickets expire after 5 minutes (`agent.rs` reaper). TOTP accepts the previous and next 30-second step for clock drift (`totp.rs` `verify`), so a code stays valid for longer than 30 s. **Close:** accept only the current and previous step, or record the drift window as a deviation. |
| V6.5.6 | 3 | Any factor can be revoked | Met | `pit mfa touchid off`, TOTP disable, quick unlock off (`ops.rs` `device.set`), `pit recovery rotate`, password change. |
| V6.5.7 | 3 | Biometrics only as a secondary factor | Met | Touch ID is used after the password, or with the device key held in this Mac's keychain (and only if the password was used within 7 days, `agent.rs` `unlock`), or for approvals inside an authenticated session. |
| V6.5.8 | 3 | TOTP checked against a trusted time source | Met | The agent's system clock (`agent.rs` `now()`); no client-supplied time. |
| V6.6.1 | 2 | PSTN/SMS OTP restrictions | N/A | No phone or SMS factors. |
| V6.6.2 | 2 | Out-of-band requests bound to the original request | Met | Approval tickets carry a SHA-256 digest of the exact operation and arguments and are honoured only for that request (`agent.rs` `digest`, `gate`). |
| V6.6.3 | 2 | Rate-limit code-based out-of-band authentication | Met | Approving a ticket needs a factor that goes through the shared throttle (`agent.rs` `gate`); AI clients cannot approve (`agent.rs` `approve`). |
| V6.6.4 | 3 | Rate-limit push notifications (push bombing) | Partly met | Every Touch ID prompt names who asks ("An AI assistant asks: …") but prompts are not rate-limited or capped. **Close:** cap prompts per client and time window, and merge identical pending requests. |
| V6.7.1 | 3 | Protect certificates used to verify assertions | N/A | No certificate-based authentication. |
| V6.7.2 | 3 | Challenge nonce at least 64 bits | N/A | No challenge-response authenticator. |
| V6.8.1 | 2 | No identity spoofing across identity providers | N/A | No identity provider. |
| V6.8.2 | 2 | Validate signatures on assertions | N/A | No identity provider. |
| V6.8.3 | 2 | SAML assertions used once | N/A | No SAML. |
| V6.8.4 | 2 | Verify IdP authentication strength claims | N/A | No identity provider. |

## V7 Session Management

The "session" is the agent's unlocked state. There are no session tokens: each connection is identified
by the kernel's peer credentials for the socket (`harden.rs` `peer`).

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V7.1.1 | 2 | Document idle and absolute timeouts, with justification against NIST SP 800-63B | Partly met | Defaults (30 min idle, 8 h maximum) are documented (`README.md`, `docs/security.md`); the maximum can be raised to 7 days (`ops.rs` `settings.set`). No justification against SP 800-63B is written. **Close:** document the rationale, and consider a lower ceiling. |
| V7.1.2 | 2 | Document the number of concurrent sessions allowed | Partly met | The agent holds exactly one session (`agent.rs` `State.session`); the documents do not say so. **Close:** state it in `docs/concepts.md`. |
| V7.1.3 | 2 | Document federated session coordination | N/A | No federation. |
| V7.2.1 | 1 | Session verification in a trusted backend | Met | Only the agent holds and checks the session (`agent.rs` `handle`). |
| V7.2.2 | 1 | Dynamically generated session tokens, not static keys | N/A | No tokens; see the note above. |
| V7.2.3 | 1 | Reference tokens unique, CSPRNG, 128 bits | N/A | No tokens. |
| V7.2.4 | 1 | New session on (re-)authentication | Met | Every unlock builds a new session and replaces any earlier one (`agent.rs` `new_session`, `unlock`). |
| V7.3.1 | 2 | Inactivity timeout | Met | Checked on every request and by a reaper thread every 5 s (`agent.rs` `Session::expired`, `run`). |
| V7.3.2 | 2 | Absolute maximum lifetime | Met | `session_secs` (default 8 h) set at unlock (`agent.rs` `new_session`). |
| V7.4.1 | 1 | Terminated sessions cannot be used | Met | `lock`, timeout and too many failed approvals drop the session; keys are zeroized on drop (`crypto.rs` `Key`); pending approvals are cleared. |
| V7.4.2 | 1 | Terminate sessions when an account is disabled | N/A | No accounts. `pit emergency destroy` removes the vault. |
| V7.4.3 | 2 | Option to end other sessions after a factor change | N/A | Only one session exists. |
| V7.4.4 | 2 | Logout easy to reach | Met | `pit lock` in the CLI and console. |
| V7.4.5 | 2 | Admins can terminate sessions | N/A | No administrators. |
| V7.5.1 | 2 | Full re-authentication before changing authentication attributes | Partly met | Password, factor, quick-unlock and recovery changes need an approval (`ops.rs` `ALWAYS_APPROVE`), but one factor or an open elevation window is enough. **Close:** require the password and the second factor for these, and leave them outside elevation windows. |
| V7.5.2 | 2 | Users can view and end active sessions | Met | `pit status` shows the session and its remaining time; `pit lock` ends it. |
| V7.5.3 | 3 | Further authentication for highly sensitive operations | Met | Reveals, `pit run`, exports, deletions and protected pushes go through `agent.rs` `gate` (`ops.rs` `needs_approval`). The owner can relax `pit run` (`run_needs_approval`) or open a time-boxed `pit elevate` window; both are documented. |
| V7.6.1 | 2 | Federated re-authentication | N/A | No federation. |
| V7.6.2 | 2 | Session creation needs consent or explicit action | N/A | Federated-session requirement. (Unlock is always an explicit action at a terminal; AI clients cannot unlock, `agent.rs` `unlock`.) |

## V8 Authorization

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V8.1.1 | 1 | Document function- and data-level access rules | Met | `docs/concepts.md` "Sessions and approvals", protected channels; `docs/security.md` "AI clients get no values". |
| V8.1.2 | 2 | Document field-level access rules | Met | `docs/concepts.md` protection table (sealed / hashed / plain: revealable, pushable). |
| V8.1.3 | 3 | Document environmental and contextual attributes used in decisions | Partly met | Inputs used: client type, peer user id, calling program, password recency, elevation window, channel protection. They are mentioned across documents but not defined in one place. **Close:** one table in `docs/security.md`. |
| V8.1.4 | 3 | Document how contextual factors drive allow/challenge/deny | Partly met | As V8.1.3. **Close:** the same table, with the action each input leads to. |
| V8.2.1 | 1 | Function-level access only with explicit permission | Met | `agent.rs` `OPEN_OPS`; `ops.rs` `AI_REFUSED`, `ALWAYS_APPROVE`, `needs_approval` (adding or changing a destination always needs approval). The client type is declared by the calling program; value-returning operations also need a person's approval for every client, as documented in `docs/security.md`. |
| V8.2.2 | 1 | Data-specific access restricted (IDOR/BOLA) | Met | Per-channel and per-scope protection (`ops.rs` `scope_protected`, `channel_protected`). |
| V8.2.3 | 2 | Field-level access restricted | Met | Listings return metadata and fingerprints only (`ops.rs` `tree`, `secret_meta`); values come only from approved reveal, run or export. |
| V8.2.4 | 3 | Adaptive controls from environment and context | Partly met | Password recency gates quick unlock; AI clients get stricter rules; protected channels always ask. No other context (such as screen lock or sleep) is used. **Close:** lock or end elevation when the screen locks or the machine sleeps. |
| V8.3.1 | 1 | Enforce authorization at a trusted service layer | Met | All decisions are made in the agent process (`agent.rs` `handle`), never in the CLI or MCP server. |
| V8.3.2 | 3 | Changes to authorization data apply immediately | Met | Policy is read from the in-memory library on every request. |
| V8.3.3 | 3 | Decide on the originating subject, not an intermediary | Met | The MCP server forwards requests as client `mcp` (`mcp.rs` `call_tool`) and the agent applies AI rules to them; the calling program is recorded (`agent.rs` `describe_peer`). |
| V8.4.1 | 2 | Cross-tenant controls | N/A | Single owner, no tenants. |
| V8.4.2 | 3 | Layered security for administrative interfaces | Partly met | The agent socket is owner-only, every connection's user id is checked (`agent.rs` `run`, `harden.rs` `peer`), and sensitive actions need approval. No device-posture or continuous checks. **Close:** as V8.2.4; optionally verify the code signature of connecting programs on macOS. |

## V11 Cryptography

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V11.1.1 | 2 | Documented key management policy and lifecycle (e.g. NIST SP 800-57) | Partly met | Key hierarchy, slots, derivation and destruction are described in `docs/security.md` and `src/vault.rs`, but not as a lifecycle policy (creation, use periods, rotation, retirement). **Close:** a key-management section covering each key's lifecycle. |
| V11.1.2 | 2 | Cryptographic inventory of keys, algorithms and where each may be used | Partly met | `docs/security.md` "What is used, and why" lists algorithms; keys and their permitted uses are not listed together. **Close:** extend it with every key (vault key, derived keys, slot keys, identity key, TOTP seed, bundle keys) and what each may protect. |
| V11.1.3 | 3 | Cryptographic discovery mechanisms | Not met | Cryptography is concentrated in `crypto.rs` but also used in `totp.rs`, `s3.rs`, `codes.rs`, `audit.rs`, `backup.rs`; nothing finds new uses automatically. **Close:** a CI check that flags new uses of crypto crates outside known modules, or a generated cryptographic bill of materials. |
| V11.1.4 | 3 | Inventory with a migration plan (including post-quantum) | Not met | No written migration plan. Symmetric parts use 256-bit keys; recipient bundles use X25519, which is not post-quantum. **Close:** a short migration plan (format versions, hybrid key exchange for recipient bundles). |
| V11.2.1 | 2 | Industry-validated implementations | Met | RustCrypto `argon2`, `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `crypto_box`; OS random source via `getrandom` (`Cargo.toml`). No hand-written primitives (`crypto.rs`). Checked against Wycheproof and RFC 9106 vectors (`tests/crypto_vectors.rs`) and RFC 6238 vectors (`tests/security_core.rs`); mutation testing covers `crypto.rs`, `codes.rs`, `shamir.rs`, `totp.rs` (`.github/workflows/assurance.yml`). |
| V11.2.2 | 2 | Crypto agility; keys and passwords replaceable, data re-encryptable | Partly met | KDF parameters are stored per slot and can be raised (`crypto.rs` `KdfParams`); password, recovery and device keys can be replaced (`vault.rs`); files carry a format version. The vault key itself cannot be rotated with re-encryption of all data, and ciphertexts carry no algorithm identifier. **Close:** a `rekey` operation and an algorithm field in sealed records. |
| V11.2.3 | 2 | At least 128 bits of security | Met | 256-bit symmetric keys; X25519 (~128-bit); Argon2id output 256 bits. Fingerprints are 48-bit labels, not security controls. |
| V11.2.4 | 3 | Constant-time operations, no short-circuit comparisons | Met | Secret comparisons use `subtle` (`crypto.rs` `ct_eq`, used in `totp.rs`, `values.rs`); Shamir arithmetic is branch-free (`shamir.rs`); primitives are constant-time implementations. |
| V11.2.5 | 3 | Fail securely; no oracle errors | Met | Every decryption failure returns the same `Error::Denied` (`crypto.rs` `open`); AEAD only, so no padding. |
| V11.3.1 | 1 | No ECB or weak padding | Met | Only AEAD modes are used. |
| V11.3.2 | 1 | Only approved ciphers and modes | Met | XChaCha20-Poly1305 (`crypto.rs` `seal`); XSalsa20-Poly1305 sealed boxes only where GitHub requires them (`rail/github.rs`). Both are approved in ASVS Appendix C. |
| V11.3.3 | 2 | Encrypted data protected against modification | Met | AEAD everywhere, with associated data binding vault, slot, generation, secret id and log position (`vault.rs` `aad`, `library_aad`; `values.rs` `aad`; `audit.rs` `aad`). |
| V11.3.4 | 3 | Nonces not reused per key; correct generation | Met | Fresh random 192-bit nonce per encryption (`crypto.rs` `seal`). |
| V11.3.5 | 3 | Encrypt-then-MAC when combining cipher and MAC | N/A | No separate cipher-plus-MAC constructions; only AEAD. |
| V11.4.1 | 1 | Only approved hash functions for cryptographic use | Partly met | SHA-256, HMAC-SHA-256 and HKDF-SHA256 are used throughout. TOTP uses HMAC-SHA-1 (`totp.rs` `hotp`), which Appendix C lists as legacy; it is kept because authenticator apps expect it. **Close:** offer SHA-256 TOTP where the owner's app supports it, and record the legacy use. |
| V11.4.2 | 2 | Passwords stored with an approved password hashing function | Met | Passwords are not stored; Argon2id (128 MiB, t=3, p=4) derives the slot key (`crypto.rs` `KdfParams::new_password`). One-way secrets use Argon2id (64 MiB, t=3) (`crypto.rs` `hash_secret`). Parameters below a floor are refused (`KdfParams::derive`). |
| V11.4.3 | 2 | Collision-resistant hashes of adequate length for integrity | Met | SHA-256 for the audit chain (`audit.rs` `line_hash`) and snapshot checksums (`backup.rs` `snapshot`). |
| V11.4.4 | 2 | Approved KDF with stretching for password-derived keys | Met | Argon2id for passwords and bundle passphrases (`crypto.rs`, `backup.rs` `seal_bundle`). |
| V11.5.1 | 2 | CSPRNG with at least 128 bits for unguessable values | Met | All keys, salts, nonces and ids come from the OS random source (`crypto.rs` `fill_random`, `random_id` 128 bits). Short slot ids and approval ticket ids are labels, not secrets. |
| V11.5.2 | 3 | Random generation secure under heavy demand | Met | The OS random source through `getrandom`; no user-space generator that could be exhausted. |
| V11.6.1 | 2 | Approved algorithms for key generation and signatures | Met | X25519 keys generated with the OS random source (`agent.rs` `init`, `crypto_box`); no signatures. |
| V11.6.2 | 3 | Approved key exchange with secure parameters | Met | X25519 sealed boxes with a fresh ephemeral key per bundle (`backup.rs` `seal_bundle`). |
| V11.7.1 | 3 | Full memory encryption for data in use | Not met | The Pit relies on the operating system's process isolation; it does not use or require memory encryption. **Close:** largely outside the application's control; document the reliance on OS isolation. |
| V11.7.2 | 3 | Minimal data exposure in use; re-encrypt as soon as possible | Partly met | Sealed values stay encrypted in memory until a push or reveal (`values.rs`), and keys are zeroized on drop. The decrypted library also holds the TOTP seed and the identity private key as plain byte vectors that are not zeroized (`model.rs` `Mfa`, `Owner`), and memory is not locked against swapping. **Close:** keep those fields sealed or in zeroizing types, and lock key memory. |

## V12 Secure Communication

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V12.1.1 | 1 | Only TLS 1.2 and 1.3; prefer the latest | Met | `ureq` with `rustls` 0.23 (`Cargo.lock`), which supports only TLS 1.2 and 1.3 and prefers 1.3. |
| V12.1.2 | 2 | Recommended cipher suites; L3 forward secrecy only | Met | rustls defaults: ECDHE key exchange with AEAD suites only. |
| V12.1.3 | 2 | Validate mTLS client certificates | N/A | No mTLS. |
| V12.1.4 | 3 | Certificate revocation checking (e.g. OCSP stapling) | Not met | The HTTPS client does not check certificate revocation. **Close:** enable revocation checking (CRLs or OCSP) in the TLS configuration. |
| V12.1.5 | 3 | Encrypted Client Hello | Not met | Not enabled in the current HTTP client. **Close:** enable ECH when moving to a client stack that supports it. |
| V12.2.1 | 1 | TLS for all HTTP connections; no fallback | Met | `rail/http.rs` `agent` (`https_only(true)`, no redirects); `s3.rs` requires `https://` endpoints. |
| V12.2.2 | 1 | External-facing services use publicly trusted certificates | N/A | The Pit runs no externally reachable service. |
| V12.3.1 | 2 | Encrypted protocols for all inbound and outbound connections | Met | Outbound: HTTPS, or SSH for SSH targets (`backup.rs` `SSH_OPTS`, `BatchMode=yes`). Local IPC uses an owner-only Unix socket, not a network. |
| V12.3.2 | 2 | TLS clients validate certificates | Met | rustls with the Mozilla root store (`webpki-roots`). |
| V12.3.3 | 2 | TLS between internal HTTP services | N/A | No internal HTTP services. |
| V12.3.4 | 2 | Internal TLS uses trusted certificates | N/A | No internal TLS. |
| V12.3.5 | 3 | Strong mutual authentication between internal services | Partly met | The agent checks the kernel-reported user id of every peer (`agent.rs` `run`, `harden.rs` `peer`), and clients check that the socket and its folder belong to them (`paths.rs` `verify_socket`). The calling program itself is recorded but not verified. **Close:** optional code-signature verification of peers on macOS. |

## V13 Configuration

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V13.1.1 | 2 | Document all communication needs, including user-supplied locations | Met | `docs/integrations.md` (Fly, Vercel, GitHub, `.env`, files, commands), `docs/backups.md` (folders, SSH, rclone, S3 with custom endpoints). |
| V13.1.2 | 3 | Document connection limits per service and behaviour at the limit | Partly met | The agent serves at most 64 connections at once and closes extra ones (`agent.rs` `MAX_CONNECTIONS`); this limit and behaviour are not documented. **Close:** document it. |
| V13.1.3 | 3 | Document resource management, timeouts and retry policies | Partly met | Backup retry back-off is documented (`docs/backups.md`); HTTP, SSH and rclone timeouts exist in code only (`rail/http.rs`, `backup.rs` `SSH_OPTS`, `RCLONE_OPTS`). **Close:** document all of them in one place. |
| V13.1.4 | 3 | Document critical secrets and a rotation schedule | Partly met | Critical secrets are described (password, recovery code, device key) and rotation is possible; no schedule is given beyond a yearly export suggestion (`docs/security.md`). **Close:** a recommended rotation schedule for the recovery code and connection tokens. |
| V13.2.1 | 2 | Backend communication authenticated without unchanging credentials | Partly met | Local IPC uses kernel peer credentials, not a shared secret. Outbound service access uses tokens the owner creates (`pit connect`) or borrows from the vendor CLI; these can be long-lived. **Close:** recommend expiring, narrowly scoped tokens in `docs/integrations.md`, and show token age. |
| V13.2.2 | 2 | Least privilege for component communication | Met | The agent runs as the owner, never as root; `pit connect` guides the owner to scoped tokens; outside tools run in a separate process (`agent.rs` `backup_watch`). |
| V13.2.3 | 2 | No default credentials | Met | None exist. |
| V13.2.4 | 2 | Allow-list of external resources | Met | The only outbound targets are fixed vendor API hosts and the destinations and backup targets the owner configured. |
| V13.2.5 | 2 | Server allow-list for outbound requests and file loads | Met | As V13.2.4; local file writes are limited by `rail/local.rs` `guard_location`. |
| V13.2.6 | 3 | Follow documented per-connection configuration | Partly met | Timeouts and retries are fixed in code, but not documented (see V13.1.2, V13.1.3). **Close:** as those rows. |
| V13.3.1 | 2 | Secrets management solution; no secrets in code; L3: hardware-backed | Partly met | The Pit is the secrets store and keeps no secrets in code or build output. Keys are software keys: the vault key lives only in agent memory, the quick-unlock key in the macOS login keychain; no hardware security module or Secure Enclave key is used. **Close:** wrap the device slot with a Secure Enclave key. |
| V13.3.2 | 2 | Least-privilege access to secrets | Met | Values open only for a push, reveal or run that policy allows (`ops.rs`); AI clients never receive values (`ops.rs` `AI_REFUSED`). |
| V13.3.3 | 3 | Crypto in an isolated security module | Partly met | Keys stay in one hardened process (`harden.rs`: no core dumps, debugger attachment refused in release builds on macOS, not dumpable on Linux), but it is not a hardware module, and some commands derive keys in the CLI process (for example file sealing in `cli.rs`). **Close:** as V13.3.1. |
| V13.3.4 | 3 | Secrets expire and are rotated per documentation | Not met | Stored secrets and connection tokens have no expiry or rotation reminder. **Close:** an optional "rotate by" date per secret, shown by `pit ls` and `pit needs`. |
| V13.4.1 | 1 | No source-control metadata deployed | Met | Shipped as a compiled binary. |
| V13.4.2 | 2 | Debug modes disabled in production | Met | Release profile: `debug = false`, `strip = true`, `panic = "abort"` (`Cargo.toml`); debugger refusal only in release (`harden.rs` `agent`). |
| V13.4.3 | 2 | No directory listings | N/A | No web server. |
| V13.4.4 | 2 | HTTP TRACE disabled | N/A | No web server. |
| V13.4.5 | 2 | Documentation and monitoring endpoints not exposed | N/A | No endpoints. The MCP tool list exposes only the documented tools (`mcp.rs` `tools`). |
| V13.4.6 | 3 | No detailed version information exposed | Met | The HTTP User-Agent sent to services is `the-pit` with no version (`rail/http.rs` `agent`). |
| V13.4.7 | 3 | Web tier serves only allowed file extensions | N/A | No web tier. |

## V14 Data Protection

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V14.1.1 | 2 | Sensitive data identified and classified | Met | Secrets are classified as sealed, hashed or plain (`docs/concepts.md`); other sensitive data (keys, connection tokens, audit log, fingerprints, addresses) is described in `docs/security.md`. |
| V14.1.2 | 2 | Protection requirements per level, including retention and logging | Partly met | Storage, reveal and push rules per level are documented; retention (5 earlier values per secret, 30 library generations, backup thinning, an audit log that is never trimmed) is not documented in one place. **Close:** a retention table. |
| V14.2.1 | 1 | No sensitive data in URLs | Met | Tokens go in the `Authorization` header (`rail/github.rs`, `rail/vercel.rs`) or the child environment (`rail/fly.rs`); values go over stdin or request bodies, never command lines or URLs (`docs/security.md`). |
| V14.2.2 | 2 | No caching of sensitive data in server components | N/A | No server components. (Outgoing backups are staged as ciphertext only, `backup.rs` `staged`.) |
| V14.2.3 | 2 | No sensitive data sent to untrusted parties | Met | No telemetry or analytics; outbound traffic only to configured destinations and backup targets. |
| V14.2.4 | 2 | Controls implemented per protection level | Met | `values.rs` `store` and `open_stored` implement each level; one-way values cannot be read back. |
| V14.2.5 | 3 | Cache only expected content types (web cache deception) | N/A | No web caching. |
| V14.2.6 | 3 | Return only the minimum sensitive data; mask by default | Met | Listings show a 48-bit keyed fingerprint, never the value (`crypto.rs` `fingerprint`, `ops.rs` `tree`); the MCP scan tool returns names and places, not values or their lengths (`mcp.rs` `pit_scan`); reveals are explicit, approved and logged; clipboard copies clear after 30 s (`cli.rs`). |
| V14.2.7 | 3 | Retention classification and automatic deletion | Partly met | Per-secret history is capped at 5 values (`values.rs` `set`), library history at 30 generations (`vault.rs` `prune_history`), and backups are thinned (`backup.rs` `thin`). The audit log grows without limit and earlier values are kept until pushed out. **Close:** configurable retention for the audit log and for earlier values. |
| V14.2.8 | 3 | Remove sensitive metadata from user files | N/A | File secrets are stored byte-for-byte on purpose (`docs/concepts.md`). |
| V14.3.1 | 1 | Clear client-side data when the session ends | Met | Ending a session drops all keys in the agent (`agent.rs`); clipboard copies are cleared (`cli.rs`); `pit run` passes values only to the one child process. |
| V14.3.2 | 2 | Anti-caching HTTP headers | N/A | No HTTP responses. |
| V14.3.3 | 2 | No sensitive data in browser storage | N/A | No browser. |

## V15 Secure Coding and Architecture

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V15.1.1 | 1 | Documented remediation time frames for vulnerable dependencies | Met | `SECURITY.md` "Dependencies and the supply chain": 7 days for high or critical advisories, 30 days otherwise. |
| V15.1.2 | 2 | SBOM of third-party components from trusted repositories | Met | CycloneDX SBOM built in CI (`.github/workflows/assurance.yml`, `sbom` job) and attested with release binaries (`.github/workflows/release.yml`); crates.io is the only allowed source (`deny.toml` `[sources]`). |
| V15.1.3 | 2 | Document time-consuming or resource-heavy functions and their defences | Not met | Argon2id derivations (128 MiB each), `pit scan` and backup sync are resource-heavy and not documented as such. **Close:** document them and their limits. |
| V15.1.4 | 3 | Document risky third-party components | Partly met | The foreign-function and Objective-C bindings are documented in `docs/assurance/unsafe.md`; external tools the rail and backups run (`flyctl`, `gh`, `rclone`, `ssh`) are not named as risky components. **Close:** a short risky-components list in `docs/security.md`. |
| V15.1.5 | 3 | Document where dangerous functionality is used | Partly met | Every `unsafe` block is listed in `docs/assurance/unsafe.md`; other dangerous functions (plaintext emergency export, `pit elevate`, `pit run`, `command` destinations) carry warnings but are not in one list. **Close:** a single list in `docs/security.md`. |
| V15.2.1 | 1 | Components within documented update time frames | Met | `cargo audit`, `cargo deny` (every advisory fails) and OSV-Scanner run on every push and daily (`.github/workflows/security.yml`); Dependabot proposes upgrades (`.github/dependabot.yml`); time frames in `SECURITY.md`. |
| V15.2.2 | 2 | Defences against resource exhaustion | Met | At most 64 concurrent connections (`agent.rs` `MAX_CONNECTIONS`), 64 MiB per request (`MAX_REQUEST`), 30 s socket read timeout (`agent.rs` `serve`), HTTP connect and request timeouts (`rail/http.rs`), and scan caps (`scan.rs`). |
| V15.2.3 | 2 | No test or development code in production | Met | Tests and fakes are not built into the release binary (`#[cfg(test)]`, `tests/`); debug-only paths are gated by `debug_assertions`. |
| V15.2.4 | 3 | Dependencies from expected repositories; no dependency confusion | Met | crates.io only, enforced by `deny.toml` (`unknown-registry` and `unknown-git` denied); CI and release builds use `--locked` (`.github/workflows/ci.yml`, `release.yml`); every Action is pinned to a commit SHA. |
| V15.2.5 | 3 | Extra isolation around dangerous functionality or risky components | Partly met | Keys are confined to the agent; outside tools for backups run in a separate process (`agent.rs` `backup_watch`). `command` destinations and vendor CLIs run unsandboxed as the owner. **Close:** document this, and consider sandbox profiles for child processes. |
| V15.3.1 | 1 | Return only required fields | Met | `ops.rs` `tree`, `secret_meta` return metadata only; MCP tools return no values (`mcp.rs`). |
| V15.3.2 | 2 | Do not follow redirects unless intended | Met | `rail/http.rs` `redirects(0)`. |
| V15.3.3 | 2 | Protect against mass assignment | Met | Each operation reads only the named arguments it expects (`ops.rs`); bundle destinations and connections are taken only with `--with-destinations` (`backup.rs` `import_bundle`). |
| V15.3.4 | 2 | Correct client IP through proxies | N/A | No network clients or proxies. |
| V15.3.5 | 2 | Strict typing; no type juggling | Met | Rust's type system; arguments are read with typed accessors (`ops.rs` `o`, `b`, `u`). |
| V15.3.6 | 2 | Prevent JavaScript prototype pollution | N/A | No JavaScript. |
| V15.3.7 | 2 | HTTP parameter pollution defences | N/A | No HTTP parameters are received. |
| V15.4.1 | 3 | Thread-safe access to shared objects | Met | Agent state is behind one `Arc<Mutex<State>>` (`agent.rs`), and a poisoned lock is recovered. |
| V15.4.2 | 3 | Atomic check-and-act (TOCTOU) | Partly met | Files are written with `create_new` and an atomic rename (`paths.rs` `write_private`); the `pit run` temporary folder is created exclusively, owner-only, with a 128-bit random name (`paths.rs` `new_private_dir`, `cli.rs`). Two checks are still separate steps from the action they guard: the throttle check and its update (`agent.rs` `throttle_check`, `throttle_fail`), and the destination path check and the write (`rail/local.rs` `guard_location`). **Close:** hold one lock across the throttle check and update; open destination files relative to the verified folder without following links. |
| V15.4.3 | 3 | Consistent locking; no deadlocks or endless retries | Met | One mutex, released before Touch ID prompts (`agent.rs` `gate`); backup retries back off to a fixed maximum (`agent.rs` `backup_watch`). |
| V15.4.4 | 3 | Fair resource allocation; no thread starvation | Met | Concurrent connection threads are capped at 64 and extra connections are closed (`agent.rs` `run`, `MAX_CONNECTIONS`). |

## V16 Security Logging and Error Handling

| ID | L | Requirement (summary) | Status | Evidence / what would close it |
| --- | --- | --- | --- | --- |
| V16.1.1 | 2 | Log inventory: events, format, storage, access, retention | Partly met | `docs/security.md` describes the audit log and its protection; there is no list of events, and no retention. **Close:** an event list and retention statement. |
| V16.2.1 | 2 | Entries include when, where, who, what | Met | Each entry has sequence, time, event, actor (client type and calling program with its parent) and details (`audit.rs` `Event`, `agent.rs` `describe_peer`). |
| V16.2.2 | 2 | Synchronized time; UTC or explicit offset | Met | Unix time in seconds (UTC) from the system clock (`model.rs` `now`). |
| V16.2.3 | 2 | Logs go only to documented places | Met | Only `~/.the-pit/log/` and its copies inside encrypted snapshots (`backup.rs` `SNAPSHOT_FILES`). |
| V16.2.4 | 2 | Logs readable by the log processor in use | Met | JSON lines; `pit log --json` gives decrypted, verified entries. |
| V16.2.5 | 2 | Sensitive data logged according to its protection level | Met | Values are never logged; only names and keyed fingerprints (`ops.rs` `push`, `secret.reveal`). |
| V16.3.1 | 2 | Log all authentication operations, success and failure | Partly met | Successful unlocks are logged with the method and the number of failed attempts before them (`agent.rs` `unlock`). Failed unlocks and failed approvals are counted (`throttle_fail`) but not written as their own entries. **Close:** record failed attempts (for example, sealed with a key that does not need the vault open) and add them to the log at the next unlock. |
| V16.3.2 | 2 | Log failed authorization; L3: all decisions and sensitive data access | Partly met | Access to values is logged, and reveals, `pit run` and exports are refused if their entry cannot be written (`agent.rs` `Session::audit_strict`, `ops.rs`); approvals are logged. Refusals (an AI client denied an operation, a declined approval) are not logged. **Close:** log every refused or denied decision. |
| V16.3.3 | 2 | Log documented security events and bypass attempts | Partly met | Changes to policy, factors, settings, connections and destinations are logged; rejected input and throttled requests are not. **Close:** as V16.3.2. |
| V16.3.4 | 2 | Log unexpected errors and control failures (e.g. TLS) | Partly met | Push failures, including network and TLS errors, are logged per destination (`ops.rs` `push`); backup failures are kept in the sync state (`backup.rs`). Agent-internal errors are not logged. **Close:** log internal errors without values. |
| V16.4.1 | 2 | Encode log data against injection | Met | Entries are serialized as JSON and encrypted (`audit.rs` `record`). |
| V16.4.2 | 2 | Logs protected from unauthorized access and modification | Met | Each entry is encrypted, chained by SHA-256 and anchored by a sealed record plus a counter in the library; `pit log` reports the first altered, removed or cut-off entry (`audit.rs` `read`). Files are owner-only. The library's rollback check uses the macOS keychain, so on Linux it is weaker (see gaps). |
| V16.4.3 | 2 | Logs sent to a separate system | Partly met | Copies of the log leave the machine inside every encrypted snapshot sent to backup targets (`backup.rs`), but there is no separate system for analysis or alerting. **Close:** an optional export of log entries (without values) to a system the owner chooses. |
| V16.5.1 | 2 | Generic error messages; no internal data | Met | Authentication failures return `access denied` with no detail (`error.rs`); errors never contain values (`rail/http.rs` `api_error`). |
| V16.5.2 | 2 | Operate securely when external resources fail | Met | Each destination fails on its own (`ops.rs` `push`); backups retry with back-off (`agent.rs` `backup_watch`); timeouts on every outside call. |
| V16.5.3 | 2 | Fail securely; no fail-open | Partly met | Approval and decryption failures deny (`agent.rs` `gate`, `crypto.rs` `open`); a failed operation restores the library; operations that hand out values fail when their audit entry cannot be written (`Session::audit_strict`). The throttle count is kept in a file, the OS keychain and process memory, highest wins (`agent.rs` `throttle_load`); on Linux there is no keychain, so only the file and process memory hold it. **Close:** an integrity-protected store for the throttle count on Linux as well. |
| V16.5.4 | 3 | Last-resort handler for unhandled errors | Partly met | Release builds abort on panic (`Cargo.toml`), which ends the session and so fails closed, but the error is not recorded and the agent stops. **Close:** catch panics per connection, log them, and keep the agent running or lock cleanly. |

---

## Gaps and follow-ups

Ordered roughly by how much each would raise assurance. IDs are the ASVS 5.0.0 requirements each one closes.

**Authentication and sessions**

1. Require a second factor at `pit init`, and bind the quick-unlock key to Secure Enclave biometric
   access control; consider FIDO2 security keys as a key slot. (V6.3.3, V13.3.1, V13.3.3)
2. Require the current password for `password.change` even inside an elevation window, and require
   password plus second factor for all authentication-setting changes. (V6.2.3, V7.5.1)
3. Decide on recovery without the enrolled second factor: keep it as a recorded deviation, or require
   the factor unless declared lost. (V6.4.3)
4. Narrow TOTP drift tolerance, or record it as a deviation; offer SHA-256 TOTP where supported.
   (V6.5.5, V11.4.1)
5. At unlock, show failed attempts and authentication changes since the last unlock. (V6.3.5, V6.3.7)
6. Cap Touch ID prompts and pending approvals per client; add per-client rate limits. (V6.6.4, V2.4.1, V2.4.2)
7. Optional breached-password filter. (V6.2.12)
8. Lock or end elevation on screen lock and sleep. (V8.2.4, V8.4.2)

**Logging and error handling**

9. Log failed unlocks, failed or declined approvals and refused operations. (V16.3.1, V16.3.2, V16.3.3)
10. Log agent-internal errors; catch panics per connection. (V16.3.4, V16.5.4)
11. Give the throttle count an integrity-protected store on Linux too (macOS already mirrors it in the
    keychain), and update it under one lock with its check. (V16.5.3, V15.4.2)
12. Optional export of value-free log entries to a separate system. (V16.4.3)

**Cryptography and key handling**

13. Keep the TOTP seed and identity private key sealed or in zeroizing types; lock key memory against
    swapping. (V11.7.2)
14. Add vault-key rotation with full re-encryption and an algorithm identifier in sealed records.
    (V11.2.2)
15. Write a key-management lifecycle, a full key inventory and a post-quantum migration plan; add a CI
    check for new cryptography uses. (V11.1.1–V11.1.4)
16. Enable certificate revocation checking, and ECH when the HTTP stack supports it. (V12.1.4, V12.1.5)
17. Rollback detection depends on the macOS keychain; Linux needs an equivalent outside the vault folder.
    (V16.4.2 note)

**Robustness and supply chain**

18. A size limit for files the CLI reads directly (such as snapshots on restore), and documentation of
    the 64 MiB request and 64-connection limits. (V5.1.1, V5.2.1, V13.1.2)
19. One shared `.env` parser for import and destination reading. (V1.5.3)
20. Destination writes: open files relative to the verified folder without following links. (V15.4.2)

**Documentation only**

21. Document: context-specific password words; the one-session model; session-timeout rationale against
    NIST SP 800-63B; all business limits; timeouts, retries and connection limits; retention (history,
    backups, audit log); contextual inputs to authorization; rotation schedule; resource-heavy
    functions; external tools as risky components, and dangerous functions in one list; a log event
    inventory.
    (V6.1.2, V7.1.1, V7.1.2, V2.1.3, V13.1.3, V13.1.4, V13.2.1, V14.1.2, V14.2.7, V8.1.3, V8.1.4,
    V15.1.3, V15.1.4, V15.1.5, V15.2.5, V16.1.1)

**Closed in 0.1.1**

- Request-size and connection caps in the agent. (V15.2.2, V15.4.4)
- Dependency fix times, `cargo audit`/`cargo deny`/OSV in CI, crates.io-only sources, `--locked`
  builds, SHA-pinned Actions, SBOM and signed build provenance for releases. (V15.1.1, V15.1.2,
  V15.2.1, V15.2.4)
- Version-free User-Agent. (V13.4.6)

**Accepted, outside the application's control**

22. Full memory encryption depends on the platform. (V11.7.1)
23. Secret expiry and rotation reminders would need a new per-secret field. (V13.3.4)

An independent review is still needed before relying on this assessment; see `SECURITY.md`.
