# The Pit

[![CI](https://github.com/OscillatingMonkey/the-pit/actions/workflows/ci.yml/badge.svg)](https://github.com/OscillatingMonkey/the-pit/actions/workflows/ci.yml)
[![Security](https://github.com/OscillatingMonkey/the-pit/actions/workflows/security.yml/badge.svg)](https://github.com/OscillatingMonkey/the-pit/actions/workflows/security.yml)
[![CodeQL](https://github.com/OscillatingMonkey/the-pit/actions/workflows/codeql.yml/badge.svg)](https://github.com/OscillatingMonkey/the-pit/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/OscillatingMonkey/the-pit/badge)](https://scorecard.dev/viewer/?uri=github.com/OscillatingMonkey/the-pit)
[![Coverage](https://img.shields.io/endpoint?url=https://oscillatingmonkey.github.io/the-pit/badges/coverage.json)](https://oscillatingmonkey.github.io/the-pit/)
[![Mutation score](https://img.shields.io/endpoint?url=https://oscillatingmonkey.github.io/the-pit/badges/mutants.json)](https://oscillatingmonkey.github.io/the-pit/)
[![Fuzzing](https://img.shields.io/endpoint?url=https://oscillatingmonkey.github.io/the-pit/badges/fuzzing.json)](https://oscillatingmonkey.github.io/the-pit/)

**An encrypted secrets vault that lives on your machine, and an integration rail that pushes
those secrets where they need to go — Fly, Vercel, GitHub Actions, local `.env` files, and more.**

- Every secret is encrypted at rest. Nothing in The Pit's folder is readable without your keys.
- You hold the keys: a password, a recovery code, and Touch ID (or an authenticator app) as a second factor.
- Projects don't read secret files any more. They ask The Pit, and The Pit pushes — and logs where everything went.
- Built for developers: a CLI, an interactive console, and an MCP server for AI assistants that can *push*
  but never *read* a secret.

```
pit project add myapp --channels production,development
pit set myapp/production STRIPE_SECRET_KEY        # prompted, hidden
pit dest add myapp/production api --kind fly --set app=myapp-api
pit push myapp/production                          # Touch ID to approve, then it's on Fly
```

> **Status: early (0.1).** The Pit is young and has not had an independent security audit. It is
> built and tested on macOS (Apple Silicon); Linux builds but is less tested, and Touch ID and the
> Keychain-backed protections are macOS-only. Keep an off-machine backup (it is automatic once you add
> a target) and report problems — see [SECURITY.md](SECURITY.md) for anything security-related.

---

## Set it up

This takes about ten minutes. It ends with The Pit running in the background, one project, and one secret.

### 1. Install

**What you need**

| | Needed for | Install (macOS) |
|---|---|---|
| macOS (tested on Apple Silicon) or Linux | everything; Touch ID and the Keychain are macOS-only | — |
| Homebrew **or** current stable Rust | installing `pit` | <https://brew.sh> or <https://rustup.rs> |
| Xcode Command Line Tools | building from source (Homebrew and Cargo both compile it) | `xcode-select --install` |
| `git` | `pit scan` (to tell committed files apart) | comes with the Command Line Tools |

Optional — install only the ones you use:

| Tool | Needed for | Install |
|---|---|---|
| `flyctl` | pushing to Fly.io | `brew install flyctl` |
| `gh` | `pit connect github --use-cli` (borrow gh's sign-in) | `brew install gh` |
| `rclone` | backups to Google Drive, Dropbox, OneDrive… | `brew install rclone` |
| `ssh` / `scp` | backups to another machine | built in |

Vercel, GitHub (with a token), S3/R2/B2 backups and `.env` files need nothing extra.

**Option A — Homebrew**

```sh
brew install oscillatingmonkey/the-pit/the-pit
```

That taps [OscillatingMonkey/homebrew-the-pit](https://github.com/OscillatingMonkey/homebrew-the-pit)
and builds the latest release from source (Homebrew installs Rust for the build — expect a few
minutes). `brew upgrade the-pit` moves you to newer releases; `brew install --HEAD
oscillatingmonkey/the-pit/the-pit` builds the current `main` instead.

**Option B — build from the repository**

```sh
git clone https://github.com/OscillatingMonkey/the-pit.git
cd the-pit
cargo install --path .
```

`cargo install` puts `pit` in `~/.cargo/bin`. Check it is on your `PATH`:

```sh
pit --version
```

You should see `pit 0.1.1`. If you installed both ways, `which pit` shows which one runs.

### 2. Create your vault

```sh
pit init
```

It asks for three things:

1. **Your name** — only used to label the vault.
2. **A password** — at least 12 characters and hard to guess. Several unrelated words work well
   (`violet orbit cascade marmalade`). Weak passwords are refused with a reason.
3. **Touch ID** (Macs with Touch ID) — answer `y` to require it after your password and for approvals.

Then it shows your **recovery code**, once:

```
PIT-R-XXXXX-XXXXX-XXXXX-…-CCCC
```

Write it on paper or put it in a password manager that is **not on this computer**. It opens your
vault if you forget your password. Type the group it asks for to confirm you have it; the screen is
then cleared.

### 3. Add a backup second factor (recommended)

```sh
pit mfa totp
```

Scan the QR code with any authenticator app (1Password, Google Authenticator, Authy…) and type the
code it shows. This gives you a second factor that works even where Touch ID doesn't
(clamshell mode, SSH sessions).

### 4. Keep The Pit running

```sh
pit service install
```

This starts The Pit's background agent now and at every login (a launchd agent on macOS,
a systemd user service on Linux). Check it:

```sh
pit service status
```

```
login service: installed
agent: running
```

The agent also backs up your vault after every change. Point it somewhere off this machine with
`pit backup target …` (iCloud, another computer over SSH, Google Drive, S3); see
[docs/backups.md](docs/backups.md).

### 5. Unlock

```sh
pit unlock
```

Enter your password, then confirm with Touch ID (or type your authenticator code). The pit stays open
for up to 8 hours, and locks itself after 30 minutes without use. `pit lock` closes it at once.

### 6. Create a project

```sh
pit project add myapp -d "My application" --channels production,development
```

A **project** is a named space for one application's secrets. **Channels** are its environments.
`production` is created *protected*: every push to it and every reveal from it asks you to approve.

### 7. Add a secret

```sh
pit set myapp/development DATABASE_URL -d "Postgres connection string for local development"
```

Paste the value when asked (it is hidden), and press Enter.

```
✓ myapp/development:DATABASE_URL set · sealed · fp 3f9a1c0b77e2
```

`fp` is a fingerprint: it identifies the value without revealing it.

### 8. Look at it

```sh
pit ls
```

```
myapp  My application
  /development  
    DATABASE_URL                       ● 3f9a1c0b77e2 sealed   Postgres connection string for local development
  /production [protected]
```

**That's it — The Pit is running, and you have a project and a secret.**

### Already have secrets somewhere?

```sh
pit import env .env.local --to myapp/development    # a .env, JSON or YAML file
pit scan ~/code/myapp --to myapp/development        # find secrets in a project and pick which to copy in
```

Both show what they would do first, never print values, and never change your project.
[docs/importing.md](docs/importing.md) has the details.

From here:

| To… | Read |
| --- | --- |
| Understand projects, channels, scopes and the three kinds of protection | [docs/concepts.md](docs/concepts.md) |
| Import a `.env`/JSON/YAML file, or scan a project for secrets | [docs/importing.md](docs/importing.md) |
| Push to Fly, Vercel, GitHub, a `.env` file, or anything else | [docs/integrations.md](docs/integrations.md) |
| Back up after every change to iCloud, another computer, Google Drive or S3 — and list, diff and restore backups | [docs/backups.md](docs/backups.md) |
| Know how it protects you, and what to do if you lose access | [docs/security.md](docs/security.md) |
| Use The Pit from an AI assistant or a script | [docs/for-machines.md](docs/for-machines.md) |
| Move a folder of `.env` files into The Pit | [docs/importing.md](docs/importing.md#from-a-folder-of-files-pit-import-secret-pit) |
| Every command | [docs/commands.md](docs/commands.md) or `pit <command> --help` |

## The console

Run `pit` with no arguments for an interactive console. Every command works without the `pit`
prefix, and `use myapp/production` sets a context so you can leave it out:

```
pit> use myapp/development
pit myapp/development> set API_KEY
pit myapp/development> push
pit myapp/development> log -n 5
```

**Tab** completes everything: commands, flags, flag values (protections, kinds, durations…), and
project, channel, secret, destination, connection and contact names, each with a short description —
never values. Nested channels complete one level at a time. As you type, a greyed **hint** shows the
rest of the word (→ accepts it) or what the command expects next. `help COMMAND` explains a command,
and a mistyped command gets suggestions — `view`, `show` and `get` all work for `reveal`.

The same completion works in your shell:

```sh
eval "$(pit completions zsh)"      # in ~/.zshrc  (bash: ~/.bashrc)
pit completions fish | source      # in ~/.config/fish/config.fish
```

In a folder linked with `pit link`, secret names complete without typing the channel. Completion
only reads names, and pressing Tab does not keep an unlocked pit from locking itself when idle.

## Uninstall

```sh
pit service uninstall
pit emergency destroy          # crypto-shreds the vault; cannot be undone
brew uninstall the-pit         # or: cargo uninstall the-pit
```

## Security assurance

The Pit's claims are meant to be checked, not trusted. Every push runs advisory scans (RustSec, OSV),
license and source checks, Semgrep and CodeQL; every week CI fuzzes every input parser, measures test
coverage and mutation score, and publishes the results at
**<https://oscillatingmonkey.github.io/the-pit/>**. The cryptography is tested against Project
Wycheproof and RFC 9106 vectors, and there is a [STRIDE threat model](docs/assurance/threat-model.md),
an [OWASP ASVS self-assessment](docs/assurance/asvs.md) and a review of every
[`unsafe` block](docs/assurance/unsafe.md). Release binaries carry signed build provenance and an SBOM.
Everything is listed, with how to reproduce it, in [docs/assurance](docs/assurance/README.md).

## Contributing and security

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security problems privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

## License

The Pit is open source under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only),
and also available under a [commercial license](COMMERCIAL.md).

- **AGPL (free).** Anyone (individuals and companies) can use The Pit for anything, including at
  work, change it and share it. If you distribute it, or let people use a modified version over a
  network, you must make your full source available to them under the AGPL too.
- **Commercial license.** For building The Pit into a product or service without the AGPL's
  obligations — closed-source, sold or hosted. See [COMMERCIAL.md](COMMERCIAL.md).

Versions 0.1.0 and 0.1.1 were released under MIT, and those copies stay MIT.
