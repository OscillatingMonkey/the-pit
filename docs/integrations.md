# The integration rail

A **push** sends one channel's selected secrets to its destinations:

```sh
pit push myapp/production                 # every destination, after a preview and a confirmation
pit push myapp/production web --dry-run   # what would be sent where, nothing sent
pit push                                  # the project/channel linked to this folder (.pit.toml)
```

Every push — dry or real, successful or not — is recorded in the audit log with the destination's
address, the connection used, who asked (CLI, console, or an AI client, with the program that ran it),
and the name and fingerprint of every key sent. `pit log --event push` shows them.

`pit diff myapp/production` compares the names in the channel with the names each destination
currently holds, without moving any values.

`pit dest kinds` prints every kind and its settings.

Services receive the **decrypted** value; The Pit decrypts `sealed` secrets only at push time. Secrets
stored one-way (`hashed`) are never sent, and every push says so. See
[Protection](concepts.md#pushed-secrets-must-be-sealed-or-plain).

---

## Fly.io — `fly`

```sh
pit connect fly                        # paste a deploy or org token (recommended)
pit connect fly --use-cli              # or: use flyctl's own sign-in
pit dest add myapp/production api --kind fly --set app=myapp-api
```

| Setting | |
| --- | --- |
| `app` | the Fly app |
| `stage` | `true` (default): secrets apply on the next `fly deploy`. `false`: Fly restarts machines now. |

Delivered through `flyctl secrets import` with values on standard input and the token in the
environment — never on a command line. Needs `flyctl` installed.

Create a scoped token with `fly tokens create deploy -a myapp-api --expiry 8760h`.

## Vercel — `vercel`

```sh
pit connect vercel                     # token from https://vercel.com/account/tokens
pit dest add myapp/production web --kind vercel --set project=myapp-web --set target=production
```

| Setting | |
| --- | --- |
| `project` | project name or id |
| `target` | `production`, `preview` or `development` |
| `team` | team id, if the project belongs to a team |
| `type` | `encrypted` (default) or `sensitive` (Vercel never shows it again, even to you) |
| `git_branch` | preview only: limit to one branch |

Delivered over HTTPS to Vercel's REST API, one idempotent upsert per variable.

Guards: an unprotected channel cannot write to the `production` target, and a protected channel writes
to one target only — production values in `preview` reach every pull request.

## GitHub Actions — `github`

```sh
pit connect github                     # fine-grained token: Secrets + Environments read/write
pit connect github --use-cli           # or: use `gh`'s sign-in
pit dest add myapp/production ci --kind github --set repo=owner/myapp --set environment=production
```

| Setting | |
| --- | --- |
| `repo` | `owner/name` (a `git@github.com:…` or `https://github.com/…` URL also works) |
| `environment` | an Actions environment; created if missing. Omit for repository secrets. |

Each value is encrypted on your machine to the repository's public key (a libsodium sealed box,
as GitHub requires) before it is sent. GitHub's API never sees plaintext.

## A `.env` file on this machine — `dotenv`

```sh
pit dest add myapp/development local --kind dotenv --set path=/Users/me/code/myapp/.env
pit push myapp/development local
```

| Setting | |
| --- | --- |
| `path` | absolute path of the file |
| `format` | `dotenv` (default), `export` (`export KEY=…`), or `json` |
| `quote` | `auto` (default; quotes values that need it), `always`, or `never` (verbatim) |

This is how "dump the secrets into a plain text file" works now: your project does not read the vault —
it asks The Pit, and The Pit writes the file it has been told about, owner-only (`0600`), atomically.

Guards:

- the file must not be inside The Pit's own folder;
- if it is inside a git repository, it must be git-ignored;
- if the file already holds a value the pit doesn't, the push stops — bring the value in with
  `pit absorb` (below), or push with `--force` to drop it.

### `pit absorb`: when a tool writes back

Some tools write to their own `.env` (an OAuth refresh token, a session cookie). `absorb` reads the
rendered file and stores every changed value back into the pit:

```sh
pit absorb myapp/development local --dry-run
pit absorb myapp/development local
```

## Files — `files`

```sh
pit set myapp/production APNS_KEY --file AuthKey_ABC123.p8
pit dest add myapp/production keys --kind files --set dir=/Users/me/code/myapp/keys --select APNS_KEY
```

Each selected secret becomes its own file (named after its original file name), `0600`.
Same location guards as `dotenv`.

## Anything else — `command`

```sh
pit dest add myapp/production render --kind command --set "run=render-cli env import --service api"
```

| Setting | |
| --- | --- |
| `run` | the command (no shell; arguments are split like a shell would) |
| `input` | `dotenv` (default) or `json` — written to the command's standard input |
| `cwd` | working directory |

The command also receives `PIT_PROJECT`, `PIT_CHANNEL` and `PIT_DESTINATION`.

---

## Running a program with secrets, without writing a file — `pit run`

```sh
pit run -c myapp/development -- npm run dev
pit run -- cargo run                               # uses .pit.toml
pit run -c slack-hooks/bamboo-forest --only SLACK_BOT_TOKEN -- ./post.sh
```

Text secrets become environment variables. File secrets are written to a private temporary folder for
the life of the program, and their paths are given as `PIT_FILE_<NAME>` (and the folder as
`PIT_FILES_DIR`); the folder is overwritten and removed when the program exits.

## Linking a repository to a channel — `.pit.toml`

```sh
cd ~/code/myapp
pit link myapp/development
```

writes a `.pit.toml` (names only, safe to commit):

```toml
project = "myapp"
channel = "development"
```

Inside that folder, `pit push`, `pit run -- …`, `pit diff` and `pit set NAME` need no project/channel.
