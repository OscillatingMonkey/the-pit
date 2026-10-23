# Sharing a secret with someone

`pit share` hands one secret from your vault to someone else's. The value is encrypted inside your
agent and decrypted inside theirs; neither of you sees it on the way, and nothing readable passes
through the chat, email or file you use to carry it.

The recipient opens a short **receive window** first. A share opens only in their vault, only once,
and only while that window is open. When it closes — used, timed out, cancelled or the pit locked —
the key it needs is gone, and the share can never be opened by anyone.

## Three steps

**1. The recipient opens a receive window** and sends the request it prints (it is not secret):

```sh
pit receive                    # open for 15 minutes; --for 5m … 24h
PIT-RQ-…
```

**2. The sender shares the secret** to that request, and sends back what it prints (not readable either):

```sh
pit share myapp/production STRIPE_KEY --to PIT-RQ-…        # or --to request.txt
PIT-SH-…                                                    # --out share.txt to write a file
```

This always asks for the sender's approval (Touch ID, code or password), and is in their `pit log`.

**3. The recipient saves it:**

```sh
pit receive PIT-SH-… --into theirapp/development           # or a file, or - for stdin
```

It is stored `sealed`, under the same name (`--as OTHER_NAME` to rename). An existing value is never
replaced unless you pass `--replace` (which asks for approval; the old value stays in history). Saving
into a protected channel asks for approval too. Once saved, the window is closed.

## The first time: compare identities

Every vault has an identity key (`pit identity`). The first time you share with someone — or receive
from them — The Pit shows their identity and asks you to compare it with what they see when they run
`pit identity`. Do it on a call or in person, not over the channel the request came through. After
that they are a **contact** and are not asked about again:

```sh
pit contacts                   # who, and their identity keys
pit contacts --forget sam      # ask again next time
```

In scripts (no terminal), pass `--trust` once you have compared.

## Windows

```sh
pit receive --list             # open windows and how long they have left
pit receive --cancel [ID]      # close one, or all of them, now
```

A window lives in the agent's memory only, never on disk or in a backup, so it closes when the pit
locks — after `idle_secs` without use as well. Keep the pit unlocked until the share arrives.
If a window closes first, open a new one and ask for a new share; an old share cannot be reused.

## What it is made of

- **Request** (`PIT-RQ-…`): the recipient's identity key, a fresh X25519 window key made for this one
  share, when the window closes, and the recipient's name.
- **Share** (`PIT-SH-…`): the secret's name, description and value, encrypted to the window key and
  authenticated with the sender's identity (`crypto_box`), then sealed to the recipient's identity key
  (sealed box). Who sent it and which window it is for are inside the authenticated part and checked
  on opening.

Opening needs both the recipient's identity key and the window key. The identity layer means only the
confirmed person's vault can open a share; the window layer means even they cannot once the window has
closed. AI clients (MCP) cannot share, open windows or save shares.
