# Concepts

## The shape of things

```
The Pit
├── global secrets                 used anywhere, by name (global:NAME)
├── connections                    delegated access to services (vercel, github, fly)
└── project  "myapp"
    ├── project secrets            seen by every channel that inherits
    └── channel "production"  [protected]
        ├── channel secrets        override project secrets of the same name
        └── destinations           where this channel's secrets go
            ├── api          → fly:myapp-api
            ├── web          → vercel:myapp-web@production
            └── github       → github:owner/myapp#production
```

### Project

A named space for one application (or a family of them). It holds secrets and channels.

### Channel

One environment of a project — `production`, `staging`, `development`, or anything else
(`bamboo-forest` for a Slack workspace, `45AP2VZPHM` for an Apple team).

- **Inherits** by default: it sees the project's secrets, and its own secrets override them.
  `pit channel add myapp/sandbox --no-inherit` makes a channel that sees only its own.
- **Protected** channels ask for your approval on every push and every reveal.
  `production` is protected automatically; protect any other with `--protected`. A project secret
  that a protected channel inherits is protected too: changing it asks for approval.
- An unprotected channel **cannot push to an address a protected channel uses** — staging can never
  overwrite production's Fly app, Vercel target, GitHub environment or file, even by mistake.

### Secret

A named value with an optional description. It lives in exactly one **scope**:

| Scope | Written as | Seen by |
| --- | --- | --- |
| global | `global` | destinations that name it as `global:NAME` |
| project | `myapp` | every inheriting channel of `myapp` |
| channel | `myapp/production` | that channel only |

A secret can be **declared** without a value (`pit declare`), so a project can list what it needs
before anyone has it. `pit needs` lists everything still empty.

A secret is **text** (most things) or a **file** (`pit set … --file key.p8`): keystores, `.p8` keys,
JSON credentials. Files are kept byte-for-byte.

## The keys of a secret, plainly

Every secret has:

| | What it is | Example |
| --- | --- | --- |
| **name** | What the program reads it as. Letters, digits, `_ - . @ /`. | `STRIPE_SECRET_KEY` |
| **description** | Optional. What it is, where it came from, what breaks without it. | "Live Stripe key — rotate in the Stripe dashboard" |
| **protection** | How it is stored. See below. | `sealed` |
| **tags** | Labels used to pick secrets for destinations. | `backend`, `web` |
| **fingerprint** | A short keyed hash. Same value → same fingerprint. Reveals nothing. | `3f9a1c0b77e2` |
| **history** | The previous five values, for `pit rollback`. | |

A name may carry a **variant** after `@`: `AUTH_SECRET@web`. It is delivered as `AUTH_SECRET`.
Use it when two destinations of one channel need different values under the same name.

### Protection: how a secret is stored

You choose, per secret (`-p` / `--protection`):

| Protection | Stored as | Can be revealed | Can be pushed | Use it for |
| --- | --- | --- | --- | --- |
| **sealed** (default) | Encrypted, two-way | Yes, with approval | Yes | API keys, tokens, passwords your apps need |
| **hashed** | Argon2id hash, one-way | Never | Never | A PIN or password you only ever need to *check* (`pit verify`) |
| **plain** | Unencrypted *inside* the encrypted vault | Yes, without approval | Yes | Non-secret settings: app names, public URLs, IDs |

Even `plain` values are never readable from a file: the whole vault is encrypted. "Plain" only means
"no approval needed to look at it once the pit is unlocked".

Change it later with `pit edit SCOPE NAME -p sealed`. Converting **to** `hashed` is one-way.

#### Pushed secrets must be sealed (or plain)

Vercel, Fly, GitHub and nearly every other service store the **real value**: they do not accept an
encrypted string, and your app would receive gibberish if they did. So The Pit decrypts a `sealed`
secret at the moment it is pushed, sends it over TLS (GitHub additionally encrypts it to the
repository's own key), and keeps it encrypted everywhere else.

A `hashed` secret has nothing left to decrypt, so it can never be pushed. The Pit keeps you informed:

- Storing a secret as `hashed` (or switching one to it) where a destination would push it stops
  and lists those destinations, and only goes ahead if you confirm in a terminal. AI clients are
  always refused.
- Adding or editing a destination warns if it selects `hashed` secrets.
- `pit ls` marks such a secret: `! one-way but pushed to N destination(s) — it will not be sent`.
- `pit push` says which secrets were **not sent** and why.

## Destinations

A destination is a place one channel's secrets go. It has:

- a **kind** — `fly`, `vercel`, `github`, `dotenv`, `files` or `command` (see [integrations](integrations.md));
- **settings** — `--set app=myapp-api`. A setting can refer to a **plain** secret in the channel as
  `{NAME}`, so an app name can live in the pit too: `--set app={FLY_APP}`. Settings are addresses —
  they appear in logs — so sealed secrets cannot be used there; credentials go through a connection
  or `token_from`;
- a **selection** — which secrets it receives:

| Selector | Picks |
| --- | --- |
| `*` (default) | every text secret the channel sees, except those tagged `address` |
| `tag:backend` | secrets tagged `backend` |
| `STRIPE_KEY` | that secret |
| `STRIPE_KEY as STRIPE_SECRET_KEY` | that secret, delivered under another name |
| `global:SENTRY_DSN` | a global secret |
| `!DEBUG_TOKEN` | removes one from the selection |

File secrets are only picked by wildcards for `files` destinations; name them explicitly elsewhere.

## Connections: delegated access

To push to a service, The Pit needs to be allowed in. `pit connect vercel` walks you through creating
a scoped token at the service, checks it with the service, and seals it in the vault. For `github`
and `fly` you can instead let The Pit borrow the CLI you are already signed in with:
`pit connect github --use-cli`. Nothing is stored in that case.

A destination uses the connection named after its kind, or `--connection NAME`, or a token kept as a
channel secret (`--set token_from=VERCEL_TOKEN`).

## Sessions and approvals

- **Locked**: the agent holds no keys. Nothing can be read or pushed.
- **Unlocked** (`pit unlock`): for a limited time, everyday work — listing, setting, pushing to
  unprotected channels, `pit run` — works without further prompts.
- **Approval**: sensitive actions ask again — Touch ID, an authenticator code, or your password.
  These are: every reveal, every `pit run`, every push to or reveal from a protected channel, exports,
  deleting things, changing connections, factors, settings or the recovery code, and every push an AI
  client asks for.
- **Elevate** (`pit elevate --for 10m`): approve once, and sensitive actions stay open for a while.
