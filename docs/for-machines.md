# The Pit for AI assistants and scripts

This page is for programs — AI coding assistants, build scripts, CI glue — and for the people who
configure them. If you are an AI assistant, read **Rules** first.

## Rules (for AI assistants)

1. **Never read, print, echo or log a secret value.** You have no tool that returns one, and the
   agent refuses value-returning requests from you. Do not try to work around this: do not open files
   under `~/.the-pit`, do not run `pit reveal`, do not run `pit run … -- env` or anything that prints
   its environment, do not `cat` a rendered `.env` file.
2. **Never ask the person to paste a secret into the chat.** Ask them to run, in their terminal:
   `pit set PROJECT/CHANNEL NAME` (it prompts with input hidden).
3. **To find out what exists**, list names: MCP `pit_list` / `pit_needs`, or `pit ls`, `pit needs`.
4. **To get secrets where a program needs them**, push: MCP `pit_push`, or `pit push PROJECT/CHANNEL`.
   For local development, the destination is a `.env` file The Pit writes; for running a command,
   suggest the person runs `pit run -c PROJECT/CHANNEL -- <command>`.
5. **When a project needs a new secret**, declare it with a description (`pit_declare`), and tell the
   person to set it. If it is something random the project generates itself (a session secret, a webhook
   signing key), you may fill an *empty* secret with `pit_generate`.
6. **Approvals are the person's.** When a tool reports that approval is needed, tell the person what is
   waiting and that they can approve with Touch ID or `pit approve <ticket>`, then retry with the
   `ticket`. Never run `pit approve` yourself.
7. **When the pit is locked**, ask the person to run `pit unlock`. Never handle their password.
8. **Anything a destination pushes stays `sealed`.** Services need the real value; a `hashed`
   (one-way) secret can never be pushed. Only declare `hashed` for values that are only ever checked.
9. **To move a project's existing secrets in**, use `pit_scan` (or `pit scan --json`) to see what is
   there (names and places, never values), then ask the person to run `pit scan <folder>` or
   `pit import env <file> --to PROJECT/CHANNEL` in their terminal. Do not read the `.env` files
   yourself, and do not edit the project to remove them until the person says the pit has them.

## MCP server

```sh
claude mcp add the-pit -- pit mcp           # Claude Code
pit mcp-config                              # JSON for other MCP clients
```

| Tool | Does | Approval |
| --- | --- | --- |
| `pit_status` | locked/unlocked, pending approvals | — |
| `pit_list` | projects, channels, secret names, descriptions, protection, set/empty, fingerprints, destinations | — |
| `pit_needs` | secrets declared but empty | — |
| `pit_declare` | declare a secret (no value) with a description | on protected channels |
| `pit_generate` | fill an **empty** secret with a random value | on protected channels |
| `pit_push` | push a channel to its destinations (`dry_run` to preview) | **always** (unless the person ran `pit elevate --ai`) |
| `pit_diff` | names in the channel vs. names at each destination | — |
| `pit_log` | recent audit entries (pushes and where they went) | — |

A push request shows the person a Touch ID prompt naming the AI client and what it asked for.
If they are away from the keyboard, the tool returns a **ticket**; the person runs `pit approve TICKET`,
and the tool is called again with `"ticket": "TICKET"`. Tickets are single-use, expire after 5 minutes,
and only approve the exact request they were issued for.

## Scripts and build tooling

Projects should not read secret files. They call The Pit:

```sh
# put this channel's secrets where they go (Fly, Vercel, GitHub, .env files)
pit push myapp/production --yes

# run something with secrets in its environment, writing nothing to disk
pit run -c myapp/development -- ./scripts/dev

# what still needs a value
pit needs myapp
```

A repository can carry a `.pit.toml` (`pit link myapp/development`) so commands inside it need no
project/channel.

**Exit codes**: `0` success; `1` failure (including a destination that failed during a push, a refused
or unanswered approval, or a locked pit).

**Without a terminal** (CI, pipes), The Pit never prompts: a locked pit or a needed approval is an
error with a message on standard error and exit code 1. Values for `pit set` may be piped on standard
input: `printf %s "$VALUE" | pit set myapp/development NAME`.

**Values `pit run` provides**:

| Variable | |
| --- | --- |
| every text secret selected | as its own variable |
| `PIT_FILE_<NAME>` | path of each file secret (temporary, `0600`, removed on exit) |
| `PIT_FILES_DIR` | the temporary folder holding them |
| `PIT_PROJECT`, `PIT_CHANNEL` | which channel this is |

## A snippet for a project's CLAUDE.md / AGENTS.md

```markdown
## Secrets

This project's secrets live in The Pit (project `myapp`; channels `production`, `development`).
Never read or print secret values, and never ask for one in chat. To see what exists use the
`the-pit` MCP tools (`pit_list`, `pit_needs`) or `pit ls myapp`. To deliver secrets, push
(`pit_push` / `pit push myapp/development`); the person approves. For a new secret, declare it with
`pit_declare` and ask the person to run `pit set myapp/<channel> NAME`. Local dev: `pit run -- <cmd>`
or `pit push myapp/development` (writes the git-ignored .env).
```
