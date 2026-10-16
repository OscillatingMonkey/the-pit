## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## Checklist

- [ ] Tests added or updated (unit, `tests/e2e.py`, or a fuzz target for new input parsing)
- [ ] No secret value can reach a log, an error, a URL, a command line or an AI (MCP) client
- [ ] New operations are in `ops::needs_approval` (and `AI_REFUSED` if AI clients must never run them)
- [ ] New `unsafe` code is listed in `docs/assurance/unsafe.md`
- [ ] `cargo fmt`, `cargo clippy --release --all-targets -- -D warnings`, `cargo test` pass
- [ ] Docs and `CHANGELOG.md` updated if behaviour changed
