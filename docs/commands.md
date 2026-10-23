# Command reference

Generated from `pit --help` by `scripts/gen-commands-doc`. Every command also works inside the console (`pit`).

```
The Pit keeps your secrets encrypted on this machine and pushes them where they need to go.

Run `pit` with no arguments for the interactive console. Start with `pit init`.

Usage: pit [COMMAND]

Commands:
  init          Create your vault: password, recovery code, second factor
  unlock        Open the pit for a while (password + second factor, or Touch ID quick unlock)
  lock          Close the pit now. Keys are wiped from memory
  status        Is the pit open, for how long, and what is waiting for approval
  elevate       Approve once and keep sensitive actions open for a few minutes
  approve       Approve a pending request (from an AI client or another terminal)
  approvals     List requests waiting for approval
  ls            Show projects, channels, secrets (names and fingerprints only) and destinations
                [alias: list]
  needs         Secrets that are declared but still empty
  project       Manage projects
  channel       Manage channels (production, staging, development, …)
  set           Set a secret's value (prompted, piped, from a file, or generated)
  declare       Declare a secret with no value yet
  describe      Set a secret's description
  edit          Rename, re-tag or change how a secret is protected
  rm            Delete a secret [aliases: delete, remove]
  mv            Move a secret to another scope (global, a project, or project/channel)
  reveal        Show a secret's value (needs approval) [aliases: view, show, get]
  verify        Check a candidate value against a secret without revealing it (works for one-way
                secrets)
  rollback      Put a secret's previous value back
  dest          Where a channel's secrets go
  connect       Delegate access to a service so The Pit can push there (vercel, github, fly)
  connections   List connections
  disconnect    Remove a connection
  push          Push a channel's secrets to its destinations
  diff          Compare what a channel holds with what each destination has (names only)
  absorb        Bring values a tool wrote into a rendered file back into the pit
  run           Run a program with a channel's secrets in its environment (nothing written to disk)
  link          Link the current folder to a project/channel (writes .pit.toml, no secrets)
  log           The audit log: every push, reveal, unlock and change
  backup        Backups, bundles and remote backup targets
  seal          Encrypt any file with a passphrase
  unseal        Decrypt a file made by `pit seal`
  recovery      Recovery code: rotate it, or split it into shares
  recover       Lost your password? Open the pit with the recovery code (or shares) and set a new
                one
  password      Change your password
  mfa           Second factors: Touch ID and authenticator codes
  quick-unlock  Touch ID quick unlock on this Mac (on|off)
  settings      Show or change settings (session length, idle lock, …)
  history       Earlier versions of the whole library, and restoring one
  identity      Your identity key, for receiving bundles and shared secrets from someone else
  share         Share one secret with someone's vault. It travels encrypted; nobody sees the value
  receive       Receive a shared secret: open a receive window, or save a share into your vault
  contacts      People you have shared secrets with, and their identity keys
  emergency     Last resort: dump everything out, or destroy the vault
  import        Import secrets: a .env/JSON/YAML file, or a folder of them
  scan          Look through a project for secrets and offer to copy them in. Never edits the
                project
  service       Run The Pit's agent as a login service (launchd / systemd)
  doctor        Health check: permissions, agent, factors, backups, leftovers
  mcp           Run the MCP server on stdio (for AI assistants)
  mcp-config    Print the MCP configuration for Claude Code and other clients
  agent         Run the agent in the foreground
  console       Open the interactive console
  completions   Print Tab completion for your shell: eval "$(pit completions zsh)" (or bash; fish: |
                source)

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## pit init

```
Create your vault: password, recovery code, second factor

Usage: pit init [OPTIONS]

Options:
      --name <NAME>  Your name, shown to people you share secrets with
      --no-touch-id  Do not require Touch ID as a second factor
  -h, --help         Print help
```

## pit unlock

```
Open the pit for a while (password + second factor, or Touch ID quick unlock)

Usage: pit unlock [OPTIONS]

Options:
      --password   Use the password even if Touch ID quick unlock is available
      --for <DUR>  Session length for this unlock, e.g. 30m, 2h
  -h, --help       Print help
```

## pit lock

```
Close the pit now. Keys are wiped from memory

Usage: pit lock

Options:
  -h, --help  Print help
```

## pit status

```
Is the pit open, for how long, and what is waiting for approval

Usage: pit status

Options:
  -h, --help  Print help
```

## pit elevate

```
Approve once and keep sensitive actions open for a few minutes

Usage: pit elevate [OPTIONS]

Options:
      --for <DUR>  e.g. 5m, 10m, 1h (max 1h) [default: 5m]
      --ai         Also cover requests from AI clients (MCP) during the window
  -h, --help       Print help
```

## pit approve

```
Approve a pending request (from an AI client or another terminal)

Usage: pit approve [TICKET]

Arguments:
  [TICKET]  The ticket to approve (from `pit approvals`); omitted, the oldest

Options:
  -h, --help  Print help
```

## pit approvals

```
List requests waiting for approval

Usage: pit approvals

Options:
  -h, --help  Print help
```

## pit ls

```
Show projects, channels, secrets (names and fingerprints only) and destinations

Usage: pit ls [TARGET]

Arguments:
  [TARGET]  Only this project or PROJECT/CHANNEL[/CHANNEL…]

Options:
  -h, --help  Print help
```

## pit needs

```
Secrets that are declared but still empty

Usage: pit needs [PROJECT]

Arguments:
  [PROJECT]  Only this project

Options:
  -h, --help  Print help
```

## pit project

```
Manage projects

Usage: pit project <COMMAND>

Commands:
  add   Create a project
  list  List projects
  edit  Rename a project or change its description
  rm    Delete a project with all its channels and secrets

Options:
  -h, --help  Print help
```

### pit project add

```
Create a project

Usage: pit project add [OPTIONS] <NAME>

Arguments:
  <NAME>  The new project's name

Options:
  -d, --description <DESCRIPTION>  What it is for (shown in listings and to AI assistants)
      --channels <CHANNELS>        Channels to create, e.g. production,staging,development
  -h, --help                       Print help
```

### pit project list

```
List projects

Usage: pit project list

Options:
  -h, --help  Print help
```

### pit project edit

```
Rename a project or change its description

Usage: pit project edit [OPTIONS] <NAME>

Arguments:
  <NAME>  The project to change

Options:
      --rename <RENAME>            Its new name
  -d, --description <DESCRIPTION>  What it is for (shown in listings and to AI assistants)
  -h, --help                       Print help
```

### pit project rm

```
Delete a project with all its channels and secrets

Usage: pit project rm <NAME>

Arguments:
  <NAME>  The project to delete, with all its channels and secrets

Options:
  -h, --help  Print help
```

## pit channel

```
Manage channels (production, staging, development, …)

Usage: pit channel <COMMAND>

Commands:
  add   Add a channel. Channels nest: PROJECT/production/eu/fra (missing parents are created)
  edit  Change a channel's description, protection, inheritance or name
  rm    Delete a channel and its secrets

Options:
  -h, --help  Print help
```

### pit channel add

```
Add a channel. Channels nest: PROJECT/production/eu/fra (missing parents are created)

Usage: pit channel add [OPTIONS] <TARGET>

Arguments:
  <TARGET>  PROJECT/CHANNEL, or PROJECT/CHANNEL/CHANNEL/… for a channel inside another

Options:
  -d, --description <DESCRIPTION>  What this channel is for
      --protected                  Require approval for every push and reveal (default for
                                   `production`). Channels inside a protected channel are always
                                   protected
      --unprotected                Do not protect it, even if it is named `production`
      --no-inherit                 Do not see the secrets of the channel (or project) it sits in
  -h, --help                       Print help
```

### pit channel edit

```
Change a channel's description, protection, inheritance or name

Usage: pit channel edit [OPTIONS] <TARGET>

Arguments:
  <TARGET>  PROJECT/CHANNEL[/CHANNEL…]

Options:
  -d, --description <DESCRIPTION>  What this channel is for
      --protected                  Require approval for every push and reveal
      --unprotected                Stop requiring approval (not possible inside a protected channel)
      --inherit <INHERIT>          See the secrets of the channel (or project) it sits in: true or
                                   false [possible values: true, false]
      --rename <RENAME>            New last part of its name; channels inside it move along
  -h, --help                       Print help
```

### pit channel rm

```
Delete a channel and its secrets

Usage: pit channel rm [OPTIONS] <TARGET>

Arguments:
  <TARGET>  PROJECT/CHANNEL[/CHANNEL…]

Options:
      --recursive  Also delete every channel inside it
  -h, --help       Print help
```

## pit set

```
Set a secret's value (prompted, piped, from a file, or generated)

Usage: pit set [OPTIONS] [ARGS]...

Arguments:
  [ARGS]...
          [SCOPE] NAME — scope is global, PROJECT or PROJECT/CHANNEL (defaults to .pit.toml)

Options:
      --file <FILE>
          Read the value from a file (stored as a file secret)

      --generate <GENERATE>
          Generate a random value of this length

      --charset <CHARSET>
          Alphabet for --generate: base64url (default), alnum, hex, symbols

          Possible values:
          - base64url: letters, digits, - and _ (default)
          - alnum:     letters and digits
          - hex:       0-9 a-f
          - symbols:   letters, digits and punctuation

  -d, --description <DESCRIPTION>
          What it is for (shown in listings and to AI assistants)

  -p, --protection <PROTECTION>
          sealed (two-way, default) | hashed (one-way) | plain

          Possible values:
          - sealed: two-way: encrypted, pushable, revealable with approval (default)
          - hashed: one-way: only verifiable, never pushed or revealed
          - plain:  not sensitive: readable whenever the pit is open

      --tag <TAG>
          Tags (comma-separated), for choosing secrets by tag

  -h, --help
          Print help (see a summary with '-h')
```

## pit declare

```
Declare a secret with no value yet

Usage: pit declare [OPTIONS] [ARGS]...

Arguments:
  [ARGS]...
          [SCOPE] NAME — scope is global, PROJECT or PROJECT/CHANNEL[/CHANNEL…] (defaults to
          .pit.toml)

Options:
  -d, --description <DESCRIPTION>
          What it is for (shown in listings and to AI assistants)

  -p, --protection <PROTECTION>
          sealed (two-way, default) | hashed (one-way) | plain

          Possible values:
          - sealed: two-way: encrypted, pushable, revealable with approval (default)
          - hashed: one-way: only verifiable, never pushed or revealed
          - plain:  not sensitive: readable whenever the pit is open

      --tag <TAG>
          Tags (comma-separated), for choosing secrets by tag

  -h, --help
          Print help (see a summary with '-h')
```

## pit describe

```
Set a secret's description

Usage: pit describe [ARGS] [ARGS]...

Arguments:
  [ARGS] [ARGS]...  [SCOPE] NAME TEXT

Options:
  -h, --help  Print help
```

## pit edit

```
Rename, re-tag or change how a secret is protected

Usage: pit edit [OPTIONS] [ARGS]...

Arguments:
  [ARGS]...
          [SCOPE] NAME — scope is global, PROJECT or PROJECT/CHANNEL[/CHANNEL…] (defaults to
          .pit.toml)

Options:
      --rename <RENAME>
          Its new name

  -p, --protection <PROTECTION>
          sealed (two-way, default) | hashed (one-way) | plain

          Possible values:
          - sealed: two-way: encrypted, pushable, revealable with approval (default)
          - hashed: one-way: only verifiable, never pushed or revealed
          - plain:  not sensitive: readable whenever the pit is open

      --tags <TAGS>
          Replace its tags (comma-separated)

  -d, --description <DESCRIPTION>
          What it is for (shown in listings and to AI assistants)

  -h, --help
          Print help (see a summary with '-h')
```

## pit rm

```
Delete a secret

Usage: pit rm [ARGS]...

Arguments:
  [ARGS]...  [SCOPE] NAME — scope is global, PROJECT or PROJECT/CHANNEL[/CHANNEL…] (defaults to
             .pit.toml)

Options:
  -h, --help  Print help
```

## pit mv

```
Move a secret to another scope (global, a project, or project/channel)

Usage: pit mv [ARGS] [ARGS]...

Arguments:
  [ARGS] [ARGS]...  [SCOPE] NAME TO — move NAME from SCOPE (or the linked channel) to TO

Options:
  -h, --help  Print help
```

## pit reveal

```
Show a secret's value (needs approval)

Usage: pit reveal [OPTIONS] [ARGS]...

Arguments:
  [ARGS]...  [SCOPE] NAME — scope is global, PROJECT or PROJECT/CHANNEL[/CHANNEL…] (defaults to
             .pit.toml)

Options:
      --copy       Copy to the clipboard (cleared automatically) instead of printing
      --out <OUT>  Write to a file (0600) instead of printing
  -h, --help       Print help
```

## pit verify

```
Check a candidate value against a secret without revealing it (works for one-way secrets)

Usage: pit verify [ARGS]...

Arguments:
  [ARGS]...  [SCOPE] NAME — scope is global, PROJECT or PROJECT/CHANNEL[/CHANNEL…] (defaults to
             .pit.toml)

Options:
  -h, --help  Print help
```

## pit rollback

```
Put a secret's previous value back

Usage: pit rollback [ARGS]...

Arguments:
  [ARGS]...  [SCOPE] NAME — scope is global, PROJECT or PROJECT/CHANNEL[/CHANNEL…] (defaults to
             .pit.toml)

Options:
  -h, --help  Print help
```

## pit dest

```
Where a channel's secrets go

Usage: pit dest <COMMAND>

Commands:
  add    pit dest add PROJECT/CHANNEL NAME --kind fly --set app=my-app
  edit   Change a destination: kind, settings, selection, connection
  rm     Remove a destination
  list   List destinations
  kinds  What each kind of destination takes

Options:
  -h, --help  Print help
```

### pit dest add

```
pit dest add PROJECT/CHANNEL NAME --kind fly --set app=my-app

Usage: pit dest add [OPTIONS] <TARGET> <NAME>

Arguments:
  <TARGET>
          PROJECT/CHANNEL[/CHANNEL…] the destination belongs to

  <NAME>
          The destination's name

Options:
      --kind <KIND>
          Where it pushes: fly, vercel, github, dotenv, files or command

          Possible values:
          - fly:     Fly.io app secrets (staged; they apply on the next deploy)
          - vercel:  Vercel project environment variables
          - github:  GitHub Actions secrets (repository or environment)
          - dotenv:  a .env file on this machine, written owner-only
          - files:   each secret as its own file in a folder (keys, certificates, JSON credentials)
          - command: pipe the secrets to a program on stdin (anything without a native adapter)

      --set <SETS>
          key=value (repeatable). Values may reference channel secrets as {NAME}

      --select <SELECT>
          Which secrets: *, tag:<t>, NAME, "NAME as ALIAS", global:NAME, !NAME (repeatable)

      --connection <CONNECTION>
          The connection whose access it uses (default: the one named after its kind)

  -d, --description <DESCRIPTION>
          What it is for (shown in listings and to AI assistants)

  -h, --help
          Print help (see a summary with '-h')
```

### pit dest edit

```
Change a destination: kind, settings, selection, connection

Usage: pit dest edit [OPTIONS] <TARGET> <NAME>

Arguments:
  <TARGET>
          PROJECT/CHANNEL[/CHANNEL…] the destination belongs to

  <NAME>
          The destination's name

Options:
      --kind <KIND>
          Where it pushes: fly, vercel, github, dotenv, files or command

          Possible values:
          - fly:     Fly.io app secrets (staged; they apply on the next deploy)
          - vercel:  Vercel project environment variables
          - github:  GitHub Actions secrets (repository or environment)
          - dotenv:  a .env file on this machine, written owner-only
          - files:   each secret as its own file in a folder (keys, certificates, JSON credentials)
          - command: pipe the secrets to a program on stdin (anything without a native adapter)

      --set <SETS>
          key=value (repeatable). Values may reference channel secrets as {NAME}

      --select <SELECT>
          Which secrets: *, tag:<t>, NAME, "NAME as ALIAS", global:NAME, !NAME (repeatable)

      --connection <CONNECTION>
          The connection whose access it uses (default: the one named after its kind)

  -d, --description <DESCRIPTION>
          What it is for (shown in listings and to AI assistants)

  -h, --help
          Print help (see a summary with '-h')
```

### pit dest rm

```
Remove a destination

Usage: pit dest rm <TARGET> <NAME>

Arguments:
  <TARGET>  PROJECT/CHANNEL[/CHANNEL…] the destination belongs to
  <NAME>    The destination to remove

Options:
  -h, --help  Print help
```

### pit dest list

```
List destinations

Usage: pit dest list [TARGET]

Arguments:
  [TARGET]  Only this PROJECT/CHANNEL[/CHANNEL…]

Options:
  -h, --help  Print help
```

### pit dest kinds

```
What each kind of destination takes

Usage: pit dest kinds

Options:
  -h, --help  Print help
```

## pit connect

```
Delegate access to a service so The Pit can push there (vercel, github, fly)

Usage: pit connect [OPTIONS] [KIND]

Arguments:
  [KIND]
          vercel | github | fly

          Possible values:
          - vercel: Vercel, with a token
          - github: GitHub, with a token or the gh CLI
          - fly:    Fly.io, with a token or flyctl

Options:
      --name <NAME>
          A name for this connection (default: its kind)

      --use-cli
          Borrow the vendor CLI's own sign-in instead of storing a token (github, fly)

      --team <TEAM>
          Vercel team id the token belongs to

      --verify <VERIFY>
          Re-check an existing connection with its service

  -h, --help
          Print help (see a summary with '-h')
```

## pit connections

```
List connections

Usage: pit connections

Options:
  -h, --help  Print help
```

## pit disconnect

```
Remove a connection

Usage: pit disconnect <NAME>

Arguments:
  <NAME>  The connection to remove

Options:
  -h, --help  Print help
```

## pit push

```
Push a channel's secrets to its destinations

Usage: pit push [OPTIONS] [TARGET] [DESTINATIONS]...

Arguments:
  [TARGET]           PROJECT/CHANNEL (defaults to .pit.toml)
  [DESTINATIONS]...  Only these destinations

Options:
      --dry-run  Show what would happen; change nothing
      --force    Overwrite local files even if they hold values the pit does not
  -y, --yes      Push without asking first
  -h, --help     Print help
```

## pit diff

```
Compare what a channel holds with what each destination has (names only)

Usage: pit diff [TARGET]

Arguments:
  [TARGET]  PROJECT/CHANNEL[/CHANNEL…] (defaults to .pit.toml)

Options:
  -h, --help  Print help
```

## pit absorb

```
Bring values a tool wrote into a rendered file back into the pit

Usage: pit absorb [OPTIONS] <TARGET> <DESTINATION>

Arguments:
  <TARGET>       PROJECT/CHANNEL[/CHANNEL…] whose rendered file to read back
  <DESTINATION>  The file destination to read back from

Options:
      --dry-run  Show what would happen; change nothing
  -h, --help     Print help
```

## pit run

```
Run a program with a channel's secrets in its environment (nothing written to disk)

Usage: pit run [OPTIONS] <COMMAND>...

Arguments:
  <COMMAND>...  The program to run, and its arguments, after --

Options:
  -c, --channel <TARGET>  PROJECT/CHANNEL (defaults to .pit.toml)
      --only <ONLY>       Only these secrets (repeatable; same syntax as destination select)
      --dest <DEST>       Use a destination's selection
  -h, --help              Print help
```

## pit link

```
Link the current folder to a project/channel (writes .pit.toml, no secrets)

Usage: pit link <TARGET>

Arguments:
  <TARGET>  PROJECT or PROJECT/CHANNEL[/CHANNEL…] this folder uses

Options:
  -h, --help  Print help
```

## pit log

```
The audit log: every push, reveal, unlock and change

Usage: pit log [OPTIONS]

Options:
  -n, --limit <LIMIT>      How many entries to show [default: 30]
      --project <PROJECT>  Only entries about this project
      --event <EVENT>      push | reveal | unlock | …
      --json               Print JSON
  -h, --help               Print help
```

## pit backup

```
Backups, bundles and remote backup targets

Usage: pit backup <COMMAND>

Commands:
  status    Where backups go, whether each holds the current vault, and any errors
  sync      Send the current vault to every target that does not have it yet
  now       Send a fresh snapshot to every target (or --to some) right now
  target    Add a remote or local backup target
  untarget  Remove a backup target
  auto      Back up after every change: on (default) or off
  list      Every backup on every target, newest first
  diff      What changed between two backups, or between a backup and now (names and fingerprints
            only)
  bundle    Export chosen projects (or everything) as an encrypted bundle
  import    Import a bundle into this vault
  restore   Replace this vault with a backup: a number from `pit backup list`, `latest`, TARGET:N,
            or a .pitvault file
  inspect   Show what a snapshot or bundle contains, without opening it

Options:
  -h, --help  Print help
```

### pit backup status

```
Where backups go, whether each holds the current vault, and any errors

Usage: pit backup status

Options:
  -h, --help  Print help
```

### pit backup sync

```
Send the current vault to every target that does not have it yet

Usage: pit backup sync [OPTIONS]

Options:
      --quiet  Print nothing unless something fails
  -h, --help   Print help
```

### pit backup now

```
Send a fresh snapshot to every target (or --to some) right now

Usage: pit backup now [OPTIONS]

Options:
      --to <TO>  Only these targets (repeatable)
      --quiet    Print nothing unless something fails
  -h, --help     Print help
```

### pit backup target

```
Add a remote or local backup target

Usage: pit backup target [OPTIONS] --kind <KIND> <NAME>

Arguments:
  <NAME>
          A name for this target

Options:
      --kind <KIND>
          dir | ssh | s3 | rclone

          Possible values:
          - dir:    a folder: iCloud Drive, Dropbox, an external disk
          - ssh:    another computer or a server, over SSH
          - s3:     S3-compatible storage: AWS, R2, B2, MinIO
          - rclone: Google Drive, OneDrive and more, via rclone

      --path <PATH>
          dir: folder (iCloud Drive, Dropbox, an external disk…)

      --dest <DEST>
          ssh: user@host:/path

      --remote <REMOTE>
          rclone: remote:path (Google Drive, OneDrive, Dropbox, B2… via rclone)

      --bucket <BUCKET>
          s3: bucket name

      --region <REGION>
          s3: region, e.g. eu-west-1 (auto for R2)

      --endpoint <ENDPOINT>
          s3: https://… for R2, B2, MinIO; omit for AWS

      --prefix <PREFIX>
          s3: folder inside the bucket

  -h, --help
          Print help (see a summary with '-h')
```

### pit backup untarget

```
Remove a backup target

Usage: pit backup untarget <NAME>

Arguments:
  <NAME>  The target to remove (its backups stay where they are)

Options:
  -h, --help  Print help
```

### pit backup auto

```
Back up after every change: on (default) or off

Usage: pit backup auto <STATE>

Arguments:
  <STATE>
          on or off

          Possible values:
          - on:  turn it on
          - off: turn it off

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### pit backup list

```
Every backup on every target, newest first

Usage: pit backup list [OPTIONS]

Options:
      --from <FROM>  Only this target, or one written out: dir:PATH, ssh:USER@HOST:PATH,
                     rclone:REMOTE:PATH
  -h, --help         Print help
```

### pit backup diff

```
What changed between two backups, or between a backup and now (names and fingerprints only)

Usage: pit backup diff [OPTIONS] <A> [B]

Arguments:
  <A>  A backup: a number from `pit backup list`, `latest`, TARGET:N, a file name or a .pitvault
       path
  [B]  Another backup; omitted, the comparison is with the vault as it is now

Options:
      --from <FROM>  Look for backups only on this target
      --password     Ask for the password the backup was made with (for a backup of a different
                     vault)
  -h, --help         Print help
```

### pit backup bundle

```
Export chosen projects (or everything) as an encrypted bundle

Usage: pit backup bundle [OPTIONS] --out <OUT>

Options:
      --project <PROJECTS>         Projects to include (repeatable); none means everything
      --out <OUT>                  Where to write the bundle
      --passphrase                 Also protect it with a passphrase (so it opens without this
                                   vault)
      --to-identity <TO_IDENTITY>  Encrypt it to someone's identity (from `pit identity`)
      --with-connections           Include connections (the access tokens destinations use)
  -h, --help                       Print help
```

### pit backup import

```
Import a bundle into this vault

Usage: pit backup import [OPTIONS] <FILE>

Arguments:
  <FILE>  The bundle to import

Options:
      --passphrase         Open it with its passphrase (asked for)
      --replace            Replace values you already have with the bundle's
      --with-destinations  Also take the bundle's destinations and connections. Only for bundles you
                           made yourself
  -h, --help               Print help
```

### pit backup restore

```
Replace this vault with a backup: a number from `pit backup list`, `latest`, TARGET:N, or a
.pitvault file

Usage: pit backup restore [OPTIONS] <WHAT>

Arguments:
  <WHAT>  A number from `pit backup list`, latest, TARGET:N, or a .pitvault file

Options:
      --from <FROM>  Look for the backup only on this target
  -h, --help         Print help
```

### pit backup inspect

```
Show what a snapshot or bundle contains, without opening it

Usage: pit backup inspect <FILE>

Arguments:
  <FILE>  A .pitvault snapshot or .pitbundle

Options:
  -h, --help  Print help
```

## pit seal

```
Encrypt any file with a passphrase

Usage: pit seal [OPTIONS] <FILE>

Arguments:
  <FILE>  The file to encrypt

Options:
      --out <OUT>  Where to write it (default: FILE.pitsealed)
      --remove     Remove the original after sealing
  -h, --help       Print help
```

## pit unseal

```
Decrypt a file made by `pit seal`

Usage: pit unseal [OPTIONS] <FILE>

Arguments:
  <FILE>  A .pitsealed file

Options:
      --out <OUT>  Where to write the decrypted file
  -h, --help       Print help
```

## pit recovery

```
Recovery code: rotate it, or split it into shares

Usage: pit recovery <COMMAND>

Commands:
  rotate  Replace the recovery code. The old one stops working

Options:
  -h, --help  Print help
```

### pit recovery rotate

```
Replace the recovery code. The old one stops working

Usage: pit recovery rotate [OPTIONS]

Options:
      --split <SPLIT>  Split into shares, e.g. 2-of-3
  -h, --help           Print help
```

## pit recover

```
Lost your password? Open the pit with the recovery code (or shares) and set a new one

Usage: pit recover

Options:
  -h, --help  Print help
```

## pit password

```
Change your password

Usage: pit password

Options:
  -h, --help  Print help
```

## pit mfa

```
Second factors: Touch ID and authenticator codes

Usage: pit mfa <COMMAND>

Commands:
  touchid   Require Touch ID after the password (on|off)
  totp      Enroll an authenticator app (RFC 6238)
  totp-off  Remove the authenticator app

Options:
  -h, --help  Print help
```

### pit mfa touchid

```
Require Touch ID after the password (on|off)

Usage: pit mfa touchid <STATE>

Arguments:
  <STATE>
          on or off

          Possible values:
          - on:  turn it on
          - off: turn it off

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### pit mfa totp

```
Enroll an authenticator app (RFC 6238)

Usage: pit mfa totp

Options:
  -h, --help  Print help
```

### pit mfa totp-off

```
Remove the authenticator app

Usage: pit mfa totp-off

Options:
  -h, --help  Print help
```

## pit quick-unlock

```
Touch ID quick unlock on this Mac (on|off)

Usage: pit quick-unlock <STATE>

Arguments:
  <STATE>
          on or off

          Possible values:
          - on:  turn it on
          - off: turn it off

Options:
  -h, --help
          Print help (see a summary with '-h')
```

## pit settings

```
Show or change settings (session length, idle lock, …)

Usage: pit settings [KEY] [VALUE]

Arguments:
  [KEY]    The setting to show or change; omitted, all of them
  [VALUE]  Its new value (durations like 15m work for *_secs)

Options:
  -h, --help  Print help
```

## pit history

```
Earlier versions of the whole library, and restoring one

Usage: pit history [OPTIONS]

Options:
      --restore <RESTORE>  Put this version back (a number from the list)
  -h, --help               Print help
```

## pit identity

```
Your identity key, for receiving bundles and shared secrets from someone else

Usage: pit identity

Options:
  -h, --help  Print help
```

## pit share

```
Share one secret with someone's vault. It travels encrypted; nobody sees the value

Usage: pit share [OPTIONS] --to <TO> [ARGS]...

Arguments:
  [ARGS]...  [SCOPE] NAME

Options:
      --to <TO>    The recipient's receive request (PIT-RQ-…, from their `pit receive`), or a file
                   holding it
      --out <OUT>  Write the share to this file instead of printing it
      --trust      Do not ask about a recipient you have not shared with before (compare their
                   identity first)
  -h, --help       Print help
```

## pit receive

```
Receive a shared secret: open a receive window, or save a share into your vault

Usage: pit receive [OPTIONS] [SHARE]

Arguments:
  [SHARE]  A share (PIT-SH-…), a file holding one, or - to read it from standard input. Without one,
           opens a receive window and prints the request to give the sender

Options:
      --into <INTO>        Where to save it: global, PROJECT or PROJECT/CHANNEL (default: the linked
                           channel)
      --as <RENAME>        Save it under another name
      --replace            Replace an existing value (the old one stays in history)
      --trust              Do not ask about a sender you have not exchanged secrets with before
                           (compare their identity first)
      --for <DUR>          How long the receive window stays open, e.g. 5m, 1h (max 24h). Locking
                           the pit closes it [default: 15m]
      --list               List open receive windows
      --cancel [<CANCEL>]  Close a receive window now (by id), or all of them
  -h, --help               Print help
```

## pit contacts

```
People you have shared secrets with, and their identity keys

Usage: pit contacts [OPTIONS]

Options:
      --forget <FORGET>  Forget a contact (by name or identity); you will be asked to confirm them
                         again
  -h, --help             Print help
```

## pit emergency

```
Last resort: dump everything out, or destroy the vault

Usage: pit emergency <COMMAND>

Commands:
  export   Dump every secret out of the vault (needs any working way in)
  destroy  Destroy the vault: crypto-shred every key slot and delete everything. Needs no key

Options:
  -h, --help  Print help
```

### pit emergency export

```
Dump every secret out of the vault (needs any working way in)

Usage: pit emergency export [OPTIONS] --out <OUT>

Options:
      --out <OUT>  Where to write the export
      --plaintext  Write plaintext: one folder per project/channel with .env files and files
  -h, --help       Print help
```

### pit emergency destroy

```
Destroy the vault: crypto-shred every key slot and delete everything. Needs no key

Usage: pit emergency destroy

Options:
  -h, --help  Print help
```

## pit import

```
Import secrets: a .env/JSON/YAML file, or a folder of them

Usage: pit import <COMMAND>

Commands:
  env         Import a .env / shell-export / JSON / YAML file (`-` reads stdin). pit import env
              .env.local --to my-app/development
  secret-pit  Import a folder laid out as PROJECT/ENVIRONMENT/*.env (see docs/importing.md)

Options:
  -h, --help  Print help
```

### pit import env

```
Import a .env / shell-export / JSON / YAML file (`-` reads stdin). pit import env .env.local --to
my-app/development

Usage: pit import env [OPTIONS] <FILES>...

Arguments:
  <FILES>...
          The .env, JSON or YAML files to read

Options:
      --to <TO>
          Where they go: global, PROJECT or PROJECT/CHANNEL (defaults to .pit.toml)

  -p, --protection <PROTECTION>
          sealed (two-way, default) | hashed (one-way) | plain

          Possible values:
          - sealed: two-way: encrypted, pushable, revealable with approval (default)
          - hashed: one-way: only verifiable, never pushed or revealed
          - plain:  not sensitive: readable whenever the pit is open

      --overwrite
          Replace existing values that differ (old values stay in history)

      --skip <SKIP>
          Keys to leave out

      --tag <TAG>
          Tags (comma-separated), for choosing secrets by tag

      --dry-run
          Show what would happen; change nothing

  -h, --help
          Print help (see a summary with '-h')
```

### pit import secret-pit

```
Import a folder laid out as PROJECT/ENVIRONMENT/*.env (see docs/importing.md)

Usage: pit import secret-pit [OPTIONS] <DIR>

Arguments:
  <DIR>  The folder, laid out PROJECT/ENVIRONMENT/*.env

Options:
      --map <MAP>  A TOML map renaming projects, channels and secrets (see examples/)
      --dry-run    Show what would happen; change nothing
  -h, --help       Print help
```

## pit scan

```
Look through a project for secrets and offer to copy them in. Never edits the project

Usage: pit scan [OPTIONS] [DIR]

Arguments:
  [DIR]
          The project folder (default: here)

Options:
      --to <TO>
          Where accepted findings go: PROJECT or PROJECT/CHANNEL (defaults to .pit.toml)

      --all
          Also list ordinary settings (ports, hosts, flags)

      --report
          Only report; do not offer to import

      --json
          Report as JSON (names, places and lengths — never values)

  -p, --protection <PROTECTION>
          How to store what you pick: sealed (default), hashed or plain

          Possible values:
          - sealed: two-way: encrypted, pushable, revealable with approval (default)
          - hashed: one-way: only verifiable, never pushed or revealed
          - plain:  not sensitive: readable whenever the pit is open

  -h, --help
          Print help (see a summary with '-h')
```

## pit service

```
Run The Pit's agent as a login service (launchd / systemd)

Usage: pit service <ACTION>

Arguments:
  <ACTION>
          install | uninstall | status | restart

          Possible values:
          - install:   start the agent at login
          - uninstall: stop starting it at login
          - status:    is it installed and running
          - restart:   restart the agent

Options:
  -h, --help
          Print help (see a summary with '-h')
```

## pit doctor

```
Health check: permissions, agent, factors, backups, leftovers

Usage: pit doctor

Options:
  -h, --help  Print help
```

## pit mcp

```
Run the MCP server on stdio (for AI assistants)

Usage: pit mcp

Options:
  -h, --help  Print help
```

## pit mcp-config

```
Print the MCP configuration for Claude Code and other clients

Usage: pit mcp-config

Options:
  -h, --help  Print help
```

## pit agent

```
Run the agent in the foreground

Usage: pit agent [OPTIONS]

Options:
      --foreground  Stay in the foreground and log to the terminal
  -h, --help        Print help
```

## pit console

```
Open the interactive console

Usage: pit console

Options:
  -h, --help  Print help
```

## pit completions

```
Print Tab completion for your shell: eval "$(pit completions zsh)" (or bash; fish: | source)

Usage: pit completions <SHELL>

Arguments:
  <SHELL>
          zsh | bash | fish

          Possible values:
          - zsh:  eval "$(pit completions zsh)" in ~/.zshrc
          - bash: eval "$(pit completions bash)" in ~/.bashrc
          - fish: pit completions fish | source, in config.fish

Options:
  -h, --help
          Print help (see a summary with '-h')
```
