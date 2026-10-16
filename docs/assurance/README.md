# Security assurance

How The Pit's security is checked, and where anyone can see the results. Everything here is free
and public: the checks run in GitHub Actions on the public source, and the documents are reviewed
with the code.

**Latest results:** <https://oscillatingmonkey.github.io/the-pit/> — coverage, mutation score,
fuzzing, advisories and the SBOM, rebuilt by CI.

> This is evidence, not a guarantee. No amount of testing proves software unbreakable, and The Pit
> has **not** had an independent audit yet. What these checks do is make known classes of mistakes
> unlikely to slip through, and make the project's claims checkable by anyone.

## Continuous checks

| Check | What it shows | Results (public) | When |
|---|---|---|---|
| **CI** | Formatting, Clippy with warnings as errors, unit tests, crypto test vectors, the end-to-end suite (93 checks on a throwaway vault) | [CI runs](https://github.com/OscillatingMonkey/the-pit/actions/workflows/ci.yml) | every push and pull request |
| **cargo-audit** | No dependency has a known vulnerability, is unmaintained or unsound (RustSec) | [Security runs](https://github.com/OscillatingMonkey/the-pit/actions/workflows/security.yml) — each run's summary page | every push, daily |
| **cargo-deny** | Every dependency comes from crates.io under an allowed license ([`deny.toml`](../../deny.toml)) | same | every push, daily |
| **OSV-Scanner** | A second advisory database (OSV.dev) agrees | same | every push, daily |
| **Semgrep** | Static analysis with the Rust and secrets rule packs | same | every push, daily |
| **CodeQL** | GitHub's semantic code analysis (security-extended queries) for Rust and the workflow files | [CodeQL runs](https://github.com/OscillatingMonkey/the-pit/actions/workflows/codeql.yml) | every push, weekly |
| **OpenSSF Scorecard** | An independent grade of the project's security practices: pinned dependencies, branch protection, token permissions, signed releases and more | [scorecard.dev](https://scorecard.dev/viewer/?uri=github.com/OscillatingMonkey/the-pit) | every push, weekly |
| **Fuzzing** | Six [cargo-fuzz](../../fuzz/fuzz_targets) targets feed millions of random inputs, under AddressSanitizer, to every parser of outside input: `.env`/JSON/YAML import, recovery codes and shares, backup snapshots, agent requests, encrypted records, authenticator codes | [report](https://oscillatingmonkey.github.io/the-pit/) | weekly and on code changes |
| **Coverage** | How much of the code the tests run (unit + vectors + end-to-end, measured together) | [report](https://oscillatingmonkey.github.io/the-pit/coverage/html/index.html) | weekly and on code changes |
| **Mutation testing** | Whether the tests notice deliberate bugs planted in the security core (crypto, recovery codes, Shamir sharing, TOTP) | [report](https://oscillatingmonkey.github.io/the-pit/) | weekly and on code changes |
| **SBOM** | Every component in the build (CycloneDX) | [report](https://oscillatingmonkey.github.io/the-pit/the-pit.cdx.json), and attached to each release | weekly, every release |
| **Signed build provenance** | A release binary was built by this repository's workflow from a given commit (SLSA provenance, Sigstore) | `gh attestation verify <file> --repo OscillatingMonkey/the-pit` | every release |
| **Dependabot** | Upgrade pull requests for Rust crates and Actions | [pull requests](https://github.com/OscillatingMonkey/the-pit/pulls) | weekly |
| **Secret scanning** | GitHub blocks pushes containing credentials | GitHub | every push |

## Reviews and assessments

| Document | What it is |
|---|---|
| [Threat model](threat-model.md) | STRIDE analysis: assets, attackers, trust boundaries, data-flow diagram, mitigations with code references, and the risks that remain |
| [OWASP ASVS 5.0 self-assessment](asvs.md) | Every applicable requirement of the OWASP Application Security Verification Standard (Level 3), marked Met / Partly / Not met with evidence |
| [OpenSSF Best Practices answers](best-practices.md) | Answers to every "passing" criterion of the OpenSSF Best Practices Badge |
| [`unsafe` code review](unsafe.md) | Every block where Rust's memory-safety checks are switched off, and why each is sound |
| [Crypto test vectors](../../tests/crypto_vectors.rs) | The Pit's encryption, key derivation and fingerprints checked against Project Wycheproof and RFC 9106 known answers, including inputs that must be rejected |
| [Security design](../security.md) | How keys, encryption, the agent and approvals work, and what The Pit does not protect against |

Gaps found by these reviews are tracked as public issues labelled
[`assurance`](https://github.com/OscillatingMonkey/the-pit/issues?q=label%3Aassurance).

## Run them yourself

```sh
cargo test --release                                   # unit tests + crypto vectors
cargo build --release && PIT_BIN=target/release/pit python3 tests/e2e.py
cargo audit && cargo deny check
osv-scanner scan source --lockfile Cargo.lock
semgrep scan --config p/rust --config p/secrets --exclude-rule rust.lang.security.unsafe-usage.unsafe-usage .
cargo +nightly fuzz run sealed -- -max_total_time=300  # or any target in fuzz/fuzz_targets
cargo mutants --file src/crypto.rs
cargo llvm-cov --html
```

All of these tools are free (`brew install cargo-audit cargo-deny osv-scanner semgrep cargo-fuzz
cargo-mutants cargo-llvm-cov`).

## Watching your own installation

- `pit log` verifies the tamper-evident audit log and lists every request with the program that made it.
- `pit doctor` checks permissions, the agent, backups and second factors.
- Free macOS tools from [Objective-See](https://objective-see.org/tools.html): **LuLu** shows any
  network connection `pit` makes (it should only contact the services you push to and your backup
  targets); **BlockBlock** alerts if anything changes the login items The Pit installs
  (`~/Library/LaunchAgents/dev.thepit.*`); **KnockKnock** lists everything set to start automatically.

## Not yet done

- **Independent audit.** Options: free audits for open-source projects (OSTIF, the Sovereign Tech
  Agency, NLnet-funded audits by Radically Open Security), Google OSS-Fuzz for continuous fuzzing
  once the project is eligible, or a paid cryptography and code audit.
- **OpenSSF Best Practices badge.** The answers are ready in [best-practices.md](best-practices.md);
  the maintainer registers the project at <https://www.bestpractices.dev>.
