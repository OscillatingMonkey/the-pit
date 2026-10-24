# Contributing

Thanks for helping. A few things matter more here than in most projects, because The Pit holds secrets.

## Ground rules

- **No code path may return or log a secret value** to an AI (MCP) client, a log, an error message,
  a URL, a command line, or the environment of a process other than the one it is meant for.
- **New operations go through the agent's policy.** Add them to `ops::dispatch` and give them a line in
  `ops::needs_approval` (and `AI_REFUSED` if an AI client must never run them).
- **No new cryptographic primitives.** Compose the existing ones in `src/crypto.rs`; bind context with
  associated data.
- **Comments say what code does and why**, not how it could be attacked.
- Keep pushed secrets decryptable: anything that writes secrets keeps the `ops::guard_one_way` check.
- **Every change comes with tests.** New behaviour gets a test that fails without it — a unit test, a
  case in `tests/e2e.py`, or both; a bug fix gets a test that reproduces the bug. Code that reads
  outside input (files, the socket, backups, bundles) also gets a fuzz target in `fuzz/`.
- **New `unsafe` code** is listed and justified in [docs/assurance/unsafe.md](docs/assurance/unsafe.md).

[AGENTS.md](AGENTS.md) has a map of the source.

## Licensing of contributions

The Pit is AGPL-3.0 and also sold under commercial licenses ([COMMERCIAL.md](COMMERCIAL.md)). To make
that possible, contributions are accepted under the [Contributor License Agreement](CLA.md): you keep
your copyright and grant the maintainer the right to include your work in both. Confirm it in your pull
request description:

> I have read CLA.md and agree to its terms for this and my future contributions.

## Building and testing

```sh
cargo build
cargo test                                   # unit tests and crypto test vectors
pip install --require-hashes -r tests/requirements.txt
cargo build --release && PIT_BIN=target/release/pit python3 tests/e2e.py
```

The end-to-end suite creates a throwaway vault in a temporary `PIT_HOME`; it never touches
`~/.the-pit`. It runs on macOS and needs no Touch ID.

Before sending a pull request:

```sh
cargo fmt
cargo clippy --release --all-targets -- -D warnings
cargo deny check && cargo audit                     # licenses, sources, advisories
PIT=target/release/pit scripts/gen-commands-doc     # if you changed a command or its help
```

Optional, the same as CI's Assurance workflow:

```sh
cargo +nightly fuzz run sealed -- -max_total_time=60    # any target in fuzz/fuzz_targets
cargo mutants --file src/crypto.rs                      # do the tests catch deliberate bugs?
cargo llvm-cov --html                                   # coverage of the Rust tests
```

## Reporting bugs

Open an issue with `pit --version`, your platform, what you ran and what happened. **Never paste a
secret value**; names and fingerprints (`pit ls`) are enough. Security problems go through
[SECURITY.md](SECURITY.md) instead.

## Releasing (maintainers)

1. Bump `version` in `Cargo.toml`, add a `## X.Y.Z — date` section to `CHANGELOG.md`, commit, and
   wait for CI to pass.
2. `scripts/release vX.Y.Z` — tags, creates the GitHub release, and updates the formula in
   [homebrew-the-pit](https://github.com/OscillatingMonkey/homebrew-the-pit).
