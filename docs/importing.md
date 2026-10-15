# Bringing existing secrets in

Two ways, both read-only toward your project: The Pit copies values **in**, and never edits, moves
or deletes the files it read.

## From a file: `pit import env`

```sh
pit import env .env.local --to myapp/development
```

| Format | Recognised by | Notes |
| --- | --- | --- |
| `.env`, `KEY=value` | anything not below | `export KEY=…` works; quotes are removed; `"…"` may span lines (PEM keys); a `#` comment directly above a key becomes its description |
| JSON | `.json` | a flat object, or nested — `{"stripe": {"secret": …}}` becomes `stripe_secret` |
| YAML | `.yml`, `.yaml` | top-level `key: value` lines only |
| stdin | `-` | read as `.env`, e.g. `vercel env pull /dev/stdout \| pit import env - --to myapp/production` |

Several files at once: `pit import env .env .env.local --to myapp/development` (a later file wins
for a key in both; you are told).

What happens:

1. A dry run is shown first: which keys are **new**, which are **already there with the same value**
   (left alone), and which are **already there with a different value**.
2. New keys are added, `sealed` unless you pass `-p plain` or `-p hashed`.
3. Keys whose value differs are kept as they are in the pit unless you confirm (or pass
   `--overwrite`). A replaced value stays in the secret's history (`pit history`).
4. Keys with no value are skipped. Declare them with `pit declare`.

`--to` defaults to the folder's `.pit.toml` link; without either you are asked. A missing project or
channel is offered for creation. `--dry-run` shows the plan and changes nothing; `--skip A,B` leaves
keys out; `--tag t` tags everything imported.

Exports from password managers or other secret tools: export to `.env` or JSON, import, then delete
the export file.

## From a project: `pit scan`

```sh
cd ~/code/myapp
pit scan                    # or: pit scan ~/code/myapp --to myapp/development
```

The Pit looks through the folder and lists what looks like a secret. **Values are never shown**:
you see a suggested name, what it looks like, its length and where it was found.

```
Found in . (values are not shown)
  1  STRIPE_SECRET_KEY                Stripe key, 34 chars
       .env.local:2
  2  DATABASE_URL                     credentials in a URL, 46 chars
       .env.local:5, src/db.ts:3
       ! committed to git — after moving it into the pit, rotate it at the service
  3  AUTH_KEY_ABC_P8                  key file, 257 chars
       config/AuthKey_ABC.p8

Copy which into the pit? [all / none / numbers like 1,3-5] 1-3
Rename any? (e.g. 2=STRIPE_KEY; Enter to keep the names)
```

Then the same dry run / confirm / add as `pit import env`. Your project is not changed.

What it looks for:

- **`.env`-style files** (`.env`, `.env.*`, `*.env`, `.envrc`, `.dev.vars`): every key with a
  value. Keys with secret-sounding names, well-known credential formats or random-looking values are
  listed; ordinary settings (`PORT=3000`) are hidden unless you pass `--all`.
- **Well-known credential formats** anywhere in the code: private keys, AWS, GitHub, Anthropic,
  OpenAI, Stripe, Slack, Google, SendGrid, npm, Fly, Supabase, Hugging Face, Shopify, Resend,
  JWTs, and URLs with a password in them (`postgres://user:pass@…`).
- **Hard-coded assignments** such as `const apiKey = "…"` with a random-looking value (marked
  *maybe*).
- **Key files**: `.pem`, `.key`, `.p8`, `.p12`, `id_rsa`…, and service-account JSON. These become
  file secrets, byte for byte.

It skips `node_modules`, build output, `.git`, lock files, binaries, files over 1 MB, symlinks, and
placeholders (`your-key-here`, `${VAR}`, `process.env.X`, `changeme`…). Example files
(`.env.example`) are only listed with `--all`.

The same value found in several places is listed once, with every place. Different values under
the same name become `NAME@file` (delivered as `NAME`, see [concepts](concepts.md)).

**Committed to git** means a file holding the value is tracked. The value is in the repository's
history even after you remove the file, so rotate it at the service once it is in the pit.

`pit scan --report` lists and stops. `pit scan --json` gives the same list as JSON (names, places,
lengths, never values) for scripts and AI assistants.

## From a folder of files: `pit import secret-pit`

If your secrets already live in a folder laid out as `DIR/<project>/<environment>/<file>.env`
(one folder per project and environment), import the whole tree at once:

```sh
pit import secret-pit ~/secrets --map my.map.toml --dry-run
pit import secret-pit ~/secrets --map my.map.toml
```

| In the folder | In The Pit |
| --- | --- |
| `<project>/` | project |
| `<project>/<environment>/` | channel (renamed through `[channels]` in the map) |
| `<target>.env` | secrets tagged `<target>`, and a destination `<target>` if the map describes one |
| a comment above a key | that secret's description |
| `pit.env` | secrets tagged `address` (plain unless the name looks sensitive), usable as `{NAME}` in destination settings |
| `github-<name>.env` | a GitHub destination `github-<name>` |
| empty values | declared, empty secrets (`pit needs`) |
| other files (`.p8`, `.jks`, `.json`, …) | file secrets |
| `*.bak*`, empty folders | skipped |
| one key with different values in two files of one environment | `KEY` and `KEY@<file>`; both are delivered as `KEY` |

The map file is optional. It names channels, describes projects and declares destinations. See
[`examples/folder-import.map.toml`](../examples/folder-import.map.toml). Back the folder up first; the
import only reads it.

## After importing

The project still reads its old files. To switch it over:

- Local development: add a `dotenv` destination that writes the `.env` file for you
  (`pit dest add myapp/development local --kind dotenv --set path=~/code/myapp/.env.local`), or run
  the app with `pit run -c myapp/development -- npm run dev` and delete the file.
- Deployed: add `vercel` / `fly` / `github` destinations and `pit push`. See
  [integrations](integrations.md).

Keep pushed secrets **sealed**. Services need the real value; see
[Protection](concepts.md#protection-how-a-secret-is-stored).
