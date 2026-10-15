# The Pit

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

**Option A — Homebrew**

```sh
brew tap oscillatingmonkey/the-pit https://github.com/OscillatingMonkey/the-pit
brew install --HEAD the-pit      # `brew install the-pit` once a release is tagged
```

**Option B — build from the repository**

You need a current stable Rust. If `cargo --version` prints nothing, install it from <https://rustup.rs>.

```sh
git clone https://github.com/OscillatingMonkey/the-pit.git
cd the-pit
cargo install --path .
```

`cargo install` puts `pit` in `~/.cargo/bin`. Check it is on your `PATH`:

```sh
pit --version
```

You should see `pit 0.1.0`.

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

## Uninstall

```sh
pit service uninstall
pit emergency destroy          # crypto-shreds the vault; cannot be undone
brew uninstall the-pit         # or: cargo uninstall the-pit
```

## Contributing and security

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security problems privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

## License

MIT — see [LICENSE](LICENSE).
