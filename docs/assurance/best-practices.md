# OpenSSF Best Practices Badge — "passing" answers

| | |
| --- | --- |
| **Project** | The Pit — <https://github.com/OscillatingMonkey/the-pit> |
| **Version** | 0.1.1 |
| **Date** | 2026-10-15 |
| **Criteria** | [OpenSSF Best Practices "passing" level](https://www.bestpractices.dev/en/criteria/0) (criterion names as in the badge project's `criteria.yml`) |

> **To get the official badge**, the project owner must sign in at <https://www.bestpractices.dev>,
> register this repository, and enter these answers there. The badge is only awarded through that
> site; this page is a ready-to-paste worksheet and does not by itself grant a badge. Answers marked
> **Unmet** say what is needed to change them.

Status counts: see the [summary](#summary) at the end. Other assurance material is indexed in
[README.md](README.md); automated results are published at <https://oscillatingmonkey.github.io/the-pit/>.

Base URL used below: `https://github.com/OscillatingMonkey/the-pit/blob/main/`

---

## Basics

### Basic project website content

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `description_good` | MUST | **Met** | The README's first lines say what it is: an encrypted local secrets vault with an integration rail that pushes secrets to Fly, Vercel, GitHub Actions and `.env` files. <https://github.com/OscillatingMonkey/the-pit/blob/main/README.md> |
| `interact` | MUST | **Met** | README covers installing (Homebrew or source), and links to CONTRIBUTING.md and SECURITY.md for feedback and contributions; issues and pull requests are open on GitHub. <https://github.com/OscillatingMonkey/the-pit/blob/main/README.md#contributing-and-security> |
| `contribution` | MUST | **Met** | Contributions are by GitHub pull request; the process, required checks and release steps are described. <https://github.com/OscillatingMonkey/the-pit/blob/main/CONTRIBUTING.md> |
| `contribution_requirements` | SHOULD | **Met** | Ground rules (no value in any log/output, every operation through the agent policy, no new crypto primitives) and required `cargo fmt` / `cargo clippy -D warnings`. <https://github.com/OscillatingMonkey/the-pit/blob/main/CONTRIBUTING.md#ground-rules> |

### FLOSS license

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `floss_license` | MUST | **Met** | AGPL-3.0-only (also offered under commercial terms, [COMMERCIAL.md](../../COMMERCIAL.md)). <https://github.com/OscillatingMonkey/the-pit/blob/main/LICENSE> |
| `floss_license_osi` | SUGGESTED | **Met** | AGPL-3.0 is OSI-approved. |
| `license_location` | MUST | **Met** | `LICENSE` at the repository root; `license = "AGPL-3.0-only"` in Cargo.toml. <https://github.com/OscillatingMonkey/the-pit/blob/main/LICENSE> |

### Documentation

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `documentation_basics` | MUST | **Met** | Setup guide in the README; concepts, importing, integrations, backups and security in `docs/`. <https://github.com/OscillatingMonkey/the-pit/blob/main/docs/concepts.md> |
| `documentation_interface` | MUST | **Met** | Every command and option (generated from the CLI's help), plus the MCP tool list, exit codes and environment variables for scripts. <https://github.com/OscillatingMonkey/the-pit/blob/main/docs/commands.md>, <https://github.com/OscillatingMonkey/the-pit/blob/main/docs/for-machines.md> |

### Other

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `sites_https` | MUST | **Met** | The repository, releases and the Homebrew tap are served by GitHub over HTTPS. |
| `discussion` | MUST | **Met** | GitHub Issues and pull requests: searchable, URL-addressable, open to anyone with a GitHub account, no proprietary client needed. <https://github.com/OscillatingMonkey/the-pit/issues> |
| `english` | SHOULD | **Met** | All documentation is in English; reports are accepted in English. |
| `maintained` | MUST | **Met** | Actively developed; 0.1.0 and 0.1.1 released 2026-10-15, with the newest release and `main` receiving fixes. <https://github.com/OscillatingMonkey/the-pit/blob/main/SECURITY.md#supported-versions> |

## Change control

### Public version-controlled source repository

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `repo_public` | MUST | **Met** | <https://github.com/OscillatingMonkey/the-pit> |
| `repo_track` | MUST | **Met** | Git records each change, its author and its time. |
| `repo_interim` | MUST | **Met** | Work is committed to `main` between releases, not only at release time. |
| `repo_distributed` | SUGGESTED | **Met** | Git. |

### Unique version numbering

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `version_unique` | MUST | **Met** | Each release has a unique version in Cargo.toml (`pit --version`). <https://github.com/OscillatingMonkey/the-pit/blob/main/Cargo.toml> |
| `version_semver` | SUGGESTED | **Met** | Semantic Versioning (`0.1.0`). |
| `version_tags` | SUGGESTED | **Met** | Each release is a git tag (`v0.1.0`), created by the release script. <https://github.com/OscillatingMonkey/the-pit/blob/main/scripts/release> |

### Release notes

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `release_notes` | MUST | **Met** | Human-written CHANGELOG with a section per release; the same text is the GitHub release body. <https://github.com/OscillatingMonkey/the-pit/blob/main/CHANGELOG.md> |
| `release_notes_vulns` | MUST | **N/A** | No publicly known vulnerability (CVE or similar) has been fixed in any release so far. Future fixes will be listed in CHANGELOG.md and in a GitHub Security Advisory. |

## Reporting

### Bug-reporting process

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `report_process` | MUST | **Met** | Bugs go to GitHub Issues; CONTRIBUTING.md says what to include and never to paste a secret value. <https://github.com/OscillatingMonkey/the-pit/blob/main/CONTRIBUTING.md#reporting-bugs> |
| `report_tracker` | SHOULD | **Met** | GitHub Issues. <https://github.com/OscillatingMonkey/the-pit/issues> |
| `report_responses` | MUST | **Met** | The project was first published in 2026-10; every report received so far has been acknowledged. *(Owner: confirm at registration time.)* |
| `enhancement_responses` | SHOULD | **Met** | As above: every enhancement request received so far has had a response. *(Owner: confirm.)* |
| `report_archive` | MUST | **Met** | GitHub Issues, including closed ones, are public and searchable. <https://github.com/OscillatingMonkey/the-pit/issues?q=is%3Aissue> |

### Vulnerability report process

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `vulnerability_report_process` | MUST | **Met** | Published in SECURITY.md, linked from the README. <https://github.com/OscillatingMonkey/the-pit/blob/main/SECURITY.md> |
| `vulnerability_report_private` | MUST | **Met** | Private vulnerability reporting is enabled; reports go through GitHub Security Advisories ("Report a vulnerability"), as SECURITY.md explains. <https://github.com/OscillatingMonkey/the-pit/security/advisories/new>, <https://github.com/OscillatingMonkey/the-pit/blob/main/SECURITY.md#reporting-a-vulnerability> |
| `vulnerability_report_response` | MUST | **Met** | SECURITY.md commits to acknowledgement within a week (under the 14-day limit). No vulnerability reports received in the last 6 months. <https://github.com/OscillatingMonkey/the-pit/blob/main/SECURITY.md#reporting-a-vulnerability> |

## Quality

### Working build system

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `build` | MUST | **Met** | `cargo build --release` rebuilds everything from source; Homebrew builds the same way. <https://github.com/OscillatingMonkey/the-pit/blob/main/Cargo.toml> |
| `build_common_tools` | SUGGESTED | **Met** | Cargo, the standard Rust build tool. |
| `build_floss_tools` | SHOULD | **Met** | Rust and Cargo are FLOSS. |

### Automated test suite

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `test` | MUST | **Met** | Unit tests (`cargo test`), cryptographic test vectors from Project Wycheproof and RFC 9106 (`tests/crypto_vectors.rs`, `tests/vectors/`), security-policy tests (`tests/security_core.rs`), and an end-to-end suite against a throwaway vault (`tests/e2e.py`) — all public, with how to run them in CONTRIBUTING.md. <https://github.com/OscillatingMonkey/the-pit/blob/main/CONTRIBUTING.md#building-and-testing>, <https://github.com/OscillatingMonkey/the-pit/blob/main/tests/vectors/README.md> |
| `test_invocation` | SHOULD | **Met** | `cargo test`, the standard Rust invocation. |
| `test_most` | SUGGESTED | **Unmet** | Coverage of unit, vector and end-to-end tests together is measured in CI (`cargo llvm-cov`) and mutation testing runs on the security core ([`assurance.yml`](https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/assurance.yml)), but no figure has been published yet — the public report at <https://oscillatingmonkey.github.io/the-pit/> has not had its first run. **Needed:** switch to Met when the first published figure shows most branches covered (above 50%). |
| `test_continuous_integration` | SUGGESTED | **Met** | Every push and pull request runs lint, unit, vector and end-to-end tests on macOS and unit tests on Linux. <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/ci.yml> |

### New functionality testing

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `test_policy` | MUST | **Met** | CONTRIBUTING.md: "Every change comes with tests" — new behaviour gets a test that fails without it, a bug fix gets a test that reproduces it, and code that reads outside input also gets a fuzz target. <https://github.com/OscillatingMonkey/the-pit/blob/main/CONTRIBUTING.md#ground-rules> |
| `tests_are_added` | MUST | **Met** | Recent major changes added tests, e.g. the commit "Test that uninstalling and reinstalling keeps every secret", and end-to-end coverage of approvals, the MCP policy and destination guards in `tests/e2e.py`. <https://github.com/OscillatingMonkey/the-pit/blob/main/tests/e2e.py> |
| `tests_documented_added` | SUGGESTED | **Met** | The policy is in the contribution instructions, and the pull request template has a "Tests added or updated" checkbox. <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/pull_request_template.md> |

### Warning flags

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `warnings` | MUST | **Met** | Rust compiler warnings plus Clippy on all targets. <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/ci.yml> |
| `warnings_fixed` | MUST | **Met** | CI fails on any warning (`cargo clippy --release --all-targets -- -D warnings`), so none are merged. |
| `warnings_strict` | SUGGESTED | **Met** | All warnings are errors in CI; the release profile also keeps integer overflow checks on. |

## Security

### Secure development knowledge

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `know_secure_design` | MUST | **Met** | The design applies least privilege (one key-holding agent; AI clients refused value operations), fail-safe defaults (protected production, approval by default), complete mediation (every operation through one policy function), open design (Kerckhoffs) and separation of keys. Written up in docs/security.md, the threat model and the OWASP ASVS self-assessment. *(Owner: confirm the primary developer's knowledge as the form asks.)* <https://github.com/OscillatingMonkey/the-pit/blob/main/docs/assurance/threat-model.md>, <https://github.com/OscillatingMonkey/the-pit/blob/main/docs/assurance/asvs.md> |
| `know_common_errors` | MUST | **Met** | Common errors for a local secrets tool are named with their counters: secrets in logs/arguments/URLs, path traversal and symlinks on writes, rollback, nonce reuse, weak password KDFs, untrusted import data, MITM. See the STRIDE tables. <https://github.com/OscillatingMonkey/the-pit/blob/main/docs/assurance/threat-model.md#5-stride-analysis> |

### Use basic good cryptographic practices

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `crypto_published` | MUST | **Met** | Only published, reviewed algorithms: Argon2id (RFC 9106), XChaCha20-Poly1305 (RFC 8439 + XChaCha), HKDF-SHA256 (RFC 5869), HMAC-SHA256, X25519 sealed boxes, RFC 6238 TOTP, Shamir sharing. <https://github.com/OscillatingMonkey/the-pit/blob/main/docs/security.md#what-is-used-and-why> |
| `crypto_call` | SHOULD | **Met** | Calls RustCrypto crates (`argon2`, `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `crypto_box`) and rustls; no hand-rolled primitives (a CONTRIBUTING.md rule). Shamir sharing over GF(2⁸) is implemented in `src/shamir.rs` as a scheme on top, with constant-time arithmetic and tests. <https://github.com/OscillatingMonkey/the-pit/blob/main/src/crypto.rs> |
| `crypto_floss` | MUST | **Met** | Every cryptographic dependency is FLOSS (MIT/Apache-2.0). |
| `crypto_keylength` | MUST | **Met** | 256-bit symmetric keys, X25519 (~128-bit security), Argon2id with 256-bit output; no smaller key sizes exist to configure. |
| `crypto_working` | MUST | **Met** | No broken algorithms or inappropriate modes; AEAD with random 192-bit nonces. |
| `crypto_weaknesses` | SHOULD | **Met** | No algorithm with known serious weaknesses is used for security. HMAC-SHA1 appears only in TOTP codes, because RFC 6238 authenticator apps require it; HMAC-SHA1 is not affected by SHA-1 collision attacks. |
| `crypto_pfs` | SHOULD | **Met** | All network key agreement is TLS via rustls, which uses only (EC)DHE key exchange. Data at rest and bundles are not key-agreement protocols. |
| `crypto_password_storage` | MUST | **Met** | The vault password is never stored; it derives a key through Argon2id with a random per-vault salt (128 MiB, 3 passes). Secrets stored "one-way" use Argon2id with a per-secret salt and constant-time comparison. <https://github.com/OscillatingMonkey/the-pit/blob/main/src/crypto.rs> |
| `crypto_random` | MUST | **Met** | All keys, nonces, salts and recovery codes come from the OS CSPRNG (`getrandom`; `OsRng` for X25519). <https://github.com/OscillatingMonkey/the-pit/blob/main/src/crypto.rs> |

### Secured delivery against man-in-the-middle (MITM) attacks

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `delivery_mitm` | MUST | **Met** | Source and releases come from GitHub over HTTPS; the Homebrew tap pins each release tarball by SHA-256; release binaries carry Sigstore-signed build provenance and an SBOM, verifiable with `gh attestation verify` as SECURITY.md describes. <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/release.yml>, <https://github.com/OscillatingMonkey/the-pit/blob/main/SECURITY.md#dependencies-and-the-supply-chain> |
| `delivery_unsigned` | MUST | **Met** | No hash is fetched over plain HTTP. The tarball's SHA-256 lives in the tap's git-tracked formula, retrieved over HTTPS. |

### Publicly known vulnerabilities fixed

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `vulnerabilities_fixed_60_days` | MUST | **Met** | No known unpatched vulnerabilities. Dependencies are checked daily by cargo-audit, cargo-deny and OSV-Scanner; Dependabot alerts and security updates are on; SECURITY.md commits to fixing dependency advisories within 7 days (high/critical) or 30 days (others). <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/security.yml>, <https://github.com/OscillatingMonkey/the-pit/blob/main/SECURITY.md#dependencies-and-the-supply-chain> |
| `vulnerabilities_critical_fixed` | SHOULD | **Met** | SECURITY.md commits to a fix or plan within 30 days for anything serious, and to fixing high or critical dependency advisories within 7 days. <https://github.com/OscillatingMonkey/the-pit/blob/main/SECURITY.md> |

### Other security issues

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `no_leaked_credentials` | MUST | **Met** | No working credentials in the repository; tests use a throwaway vault and stand-in tools (`tests/fakes/`) with dummy values. GitHub secret scanning and push protection are on, and Semgrep runs its secrets rules. |

## Analysis

### Static code analysis

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `static_analysis` | MUST | **Met** | Clippy on every change; Semgrep and cargo-deny in the security workflow; CodeQL (Rust and Actions, security-extended queries). <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/security.yml>, <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/codeql.yml> |
| `static_analysis_common_vulnerabilities` | SUGGESTED | **Met** | CodeQL security-extended queries and Semgrep's Rust and secrets rule packs look for common vulnerability patterns; OpenSSF Scorecard checks repository practices. <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/codeql.yml>, <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/scorecard.yml> |
| `static_analysis_fixed` | MUST | **Met** | Confirmed medium-or-higher findings are fixed before release; Clippy findings block merging. |
| `static_analysis_often` | SUGGESTED | **Met** | Clippy, Semgrep and CodeQL run on every push to `main` and every pull request; Semgrep also runs daily and CodeQL weekly. |

### Dynamic code analysis

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| `dynamic_analysis` | SUGGESTED | **Met** | Six cargo-fuzz targets (imports, recovery codes, snapshots, agent requests, sealed records, authenticator codes) run under AddressSanitizer weekly and on code changes; mutation testing (`cargo mutants`) runs on the security core. <https://github.com/OscillatingMonkey/the-pit/blob/main/fuzz/fuzz_targets>, <https://github.com/OscillatingMonkey/the-pit/blob/main/.github/workflows/assurance.yml> |
| `dynamic_analysis_unsafe` | SUGGESTED | **Met** | The code is Rust. Every `unsafe` block (OS calls for process hardening, peer credentials, Touch ID) is listed and justified in unsafe.md, exercised by the end-to-end suite, and fuzzing runs with AddressSanitizer. <https://github.com/OscillatingMonkey/the-pit/blob/main/docs/assurance/unsafe.md> |
| `dynamic_analysis_enable_assertions` | SUGGESTED | **Met** | cargo-fuzz builds with debug assertions and overflow checks enabled by default; release builds also keep overflow checks on (`overflow-checks = true`). |
| `dynamic_analysis_fixed` | MUST | **Met** | Confirmed medium-or-higher findings from fuzzing are fixed, and the crashing input is kept as a regression test. |

---

## Summary

| Status | Count | Criteria |
| --- | --- | --- |
| **Met** | 65 | All others |
| **Unmet** | 1 | `test_most` (SUGGESTED) — pending the first published coverage figure |
| **N/A** | 1 | `release_notes_vulns` |

**Blocking the passing badge:** nothing. Every MUST criterion is Met or N/A. `test_most` is only
SUGGESTED; switch it to Met once the first coverage figure is published at
<https://oscillatingmonkey.github.io/the-pit/>.

**Owner to confirm at registration:** `report_responses`, `enhancement_responses`,
`know_secure_design`, `know_common_errors` — these are statements about people and history, which the
form asks the maintainer to vouch for.

Related: [assurance index](README.md) · [threat model](threat-model.md) · [ASVS self-assessment](asvs.md) · [`unsafe` review](unsafe.md) · [docs/security.md](../security.md) · [SECURITY.md](../../SECURITY.md)
