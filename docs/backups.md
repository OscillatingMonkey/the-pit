# Backups

Services take a secret and never give it back, so The Pit is the only place your secrets stay
readable. Back it up somewhere other than this computer.

## Two kinds of backup

| | Snapshot (`.pitvault`) | Bundle (`.pitbundle`) |
| --- | --- | --- |
| Contains | the whole vault, as the encrypted files on disk | chosen projects (or everything), re-encrypted |
| Needs the pit unlocked to make | **no** — so it is sent automatically, even while locked | yes, and an approval |
| Opens with | the password or recovery code current **when it was taken** | this vault, and optionally a passphrase or someone's identity key |
| Use it for | disaster recovery | moving projects between vaults or people; a portable export |

Neither ever leaves the machine unencrypted. Remote targets receive the same ciphertext a local folder would.

## Snapshots: every change, everywhere

A snapshot is sent **after every change**. A few seconds after anything in the vault changes (a
secret set, a destination added, a password changed), every backup target is sent the new vault.
Nothing is on an hourly timer.

If a target cannot be reached (the laptop is offline, the server is asleep), The Pit keeps trying:

- The agent retries after 30 s, 1, 2, 5 and 10 minutes, then every 15 minutes.
- The agent checks again whenever it starts, so changes made before the computer was switched off go
  out at the next login.
- A small catch-up job (installed by `pit service install`) runs every 15 minutes and on wake, even
  if the agent is not running. It does nothing unless some target is behind.

Each target is tracked separately: a target that already holds the current vault is not sent it
again, and one that is behind gets the newest vault (not every missed step).

```sh
pit backup status                    # each target: up to date, or behind and why
pit backup sync                      # send now to every target that is behind
pit backup now                       # send a fresh snapshot to every target, behind or not
pit backup auto off                  # stop automatic backups (`on` to resume)
```

A copy always goes to `~/.the-pit/backups`. Add places off this machine below.

**What is kept.** On every target: every snapshot from the last two days, then the newest of each
day for 60 days, then the newest of each month, and never fewer than the 30 most recent. A snapshot
is a few kilobytes to a few hundred, so this costs very little.

### A folder — iCloud Drive, Dropbox, Google Drive for desktop, an external disk

```sh
pit backup target icloud --kind dir --path "~/Library/Mobile Documents/com~apple~CloudDocs/The Pit backups"
pit backup target usb --kind dir --path /Volumes/Backup/the-pit
```

### Another computer or a server, over SSH

```sh
pit backup target home-server --kind ssh --dest me@home-server:the-pit-backups
```

The path is relative to that account's home folder (or absolute). The folder is created, readable
only by that account. This needs key-based login that works without a prompt; check with
`ssh -o BatchMode=yes me@home-server true`. No passwords are typed or stored.

### Google Drive, OneDrive, Dropbox (API) and 70 others — via rclone

```sh
brew install rclone
rclone config                        # create a remote, e.g. "gdrive" (a browser sign-in)
pit backup target gdrive --kind rclone --remote gdrive:the-pit-backups
```

### S3-compatible storage — AWS S3, Cloudflare R2, Backblaze B2, MinIO

```sh
pit backup target r2 --kind s3 --bucket my-pit-backups --region auto \
    --endpoint https://<account-id>.r2.cloudflarestorage.com --prefix the-pit/
pit backup target aws --kind s3 --bucket my-pit-backups --region us-east-1
```

You are asked for an access key; it is kept in the macOS Keychain, not in any file. Give that key
**write-only** permission on that bucket: a leaked key then cannot read or delete your backups.
Expire old snapshots with the bucket's lifecycle rules. To restore, add the target again with a
key that can read.

Adding a target sends it the current vault straight away, so a mistake shows up at once.

## Finding, comparing and restoring a backup

```sh
pit backup list                      # every backup on every target, newest first
```

```
    #  taken                  gen  local     gdrive    home-ser
    1  2026-10-15 09:12:04     47  ✓         ✓         ✓
    2  2026-10-15 08:55:40     46  ✓         ✓         ✓
    3  2026-10-14 22:01:13     45  ✓         ✓         ·
```

`gen` is the vault's generation: it goes up by one with every change.

Name a backup by its **number** in that list, `latest`, `TARGET:N` (e.g. `gdrive:1`), its file
name, or a path to a `.pitvault` file.

### Compare

```sh
pit backup diff 3                    # what changed between backup 3 and now
pit backup diff 3 1                  # between two backups
pit backup diff gdrive:latest        # is Google Drive's newest copy the same as now?
```

```
+ secret        myapp/production STRIPE_WEBHOOK_SECRET
~ secret        myapp/production DATABASE_URL  (value changed (3f9a1c0b77e2 → 9b20d4e1aa07))
- destination   myapp/staging web
~ setting       idle_secs  (1800 → 900)
```

Secrets are compared by fingerprint, never by value. Diffs cover projects, channels, secrets (value,
protection, description, tags), destinations, connections, settings and second factors. Diffing
needs the pit unlocked. A backup of a *different* vault opens with `--password` (the password it was
made with).

### Restore

```sh
pit backup restore 3                 # or: latest, gdrive:2, a file name, a .pitvault path
pit unlock
```

Before replacing anything, restore shows what going back would undo (when the pit is unlocked), and
asks. The vault being replaced is saved first, as `~/.the-pit/backups/before-restore-…`, so a restore
can itself be undone. The restored vault opens with the password (or recovery code) that was current
when the backup was taken.

### On a new computer

Nothing is configured there yet, so write the target out with `--from`:

```sh
pit backup list --from ssh:me@home-server:the-pit-backups
pit backup restore latest --from ssh:me@home-server:the-pit-backups
pit backup restore latest --from rclone:gdrive:the-pit-backups        # after `rclone config`
pit backup restore latest --from "dir:~/Library/Mobile Documents/com~apple~CloudDocs/The Pit backups"
```

Then `pit unlock` with your password (or `pit recover` with the recovery code), set up a second
factor again if it was Touch ID (`pit mfa touchid on`), and `pit service install`. For S3, add the
target first with read keys.

`pit backup inspect FILE` checks a snapshot file is intact without opening it.

## Bundles

```sh
pit backup bundle --project myapp --out myapp.pitbundle                 # opens only in this vault
pit backup bundle --project myapp --out myapp.pitbundle --passphrase    # opens anywhere with the passphrase
pit backup bundle --out everything.pitbundle --passphrase --with-connections
pit backup bundle --project myapp --out for-sam.pitbundle --to-identity PIT-ID-…   # only Sam can open it
pit backup import myapp.pitbundle [--passphrase] [--replace]
```

Import merges: projects that don't exist are added; in existing ones, secrets you already have are kept
(and listed) unless you pass `--replace`.

`pit identity` prints your identity key. Share it freely; it only lets people encrypt *to* you.

## Encrypting any file — `pit seal`

```sh
pit seal old-secrets.tar.gz --remove          # → old-secrets.tar.gz.pitsealed, original overwritten and removed
pit unseal old-secrets.tar.gz.pitsealed
```

Argon2id + XChaCha20-Poly1305 with a passphrase you choose. Independent of the vault.
