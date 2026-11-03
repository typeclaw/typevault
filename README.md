# typevault

A CLI-first secrets vault for agents. `.env` exposes too much; password managers are too heavy.

> Each session gets exactly the secrets its grant allows, every read leaves a trail, and secrets stay out of transcripts.

- **Git-friendly:** the vault is a directory of age-encrypted, signed files. Keep one per project in `.typevault/` and
  commit it; the keys never live there.
- **Groups are keys:** each group has a keypair; groups can include others (`trusted` includes `member`). Access is enforced by cryptography, not by checks.
- **Grants, not keys:** agents hold short-lived grants. A daemon holds the keys, serves values and audits every read.
- **No human in the loop:** an operator-signed ceiling caps what each admin socket may grant.
- **Reading = using:** if a grant can use a secret it can read it, so put secrets in a group only if that group may see them.

## Install

```sh
bun add -g typevault
```

## Quick start

```sh
typevault init                                   # creates .typevault/ here with a `default` group; -g for global

# With one group, set needs no --group
printf '%s' "$OPENAI_KEY" | typevault set tv://openai --type api_key --stdin
typevault set tv://github/bot --type password --field username=bot --stdin < password.txt
echo '{"access_token":"…","refresh_token":"…"}' | typevault set tv://google --type oauth --stdin-json

# Split reach once agents need different access
typevault group add trusted
typevault group include trusted default          # trusted reaches everything default reaches
printf '%s' "$STRIPE_KEY" | typevault set tv://stripe --type api_key --group trusted --stdin

# Hand an agent a grant instead of a key (the daemon starts automatically)
export TYPEVAULT_GRANT=$(typevault grant --group default --label session:abc)

typevault ls
typevault run -- psql                            # secrets arrive as env vars; output is redacted
typevault run --only tv://github/bot -- agent-browser fill @e3 "$GITHUB_BOT_PASSWORD"
```

## Project and global vaults

Like `bun` and `npm`, every command works on the project unless you pass `-g`:

```sh
typevault ls                                     # the nearest .typevault/ up from the working directory
typevault -g ls                                  # the global vault in ~/.config/typevault
```

Without `-g`, a command run outside any project fails instead of falling back to the global vault, so a secret never
lands in the wrong one. `-g` goes before `--` in `run`; `TYPEVAULT_GLOBAL=1` does the same, and an explicit
`TYPEVAULT_DIR` always selects the vault kept whole at that path.

A project vault holds only ciphertext and signed manifests, so commit `.typevault/` as is. Its keys live under
`~/.config/typevault/vaults/<id>/`, where `<id>` comes from the vault's operator key, so every clone of the project
finds them. Each checkout keeps its own trust pin, audit log and daemon under `~/.config/typevault/checkouts/<id>/`. A collaborator gets access with `TYPEVAULT_KEY` (`typevault key export`) or a
grant, as with the global vault.

## Naming

`tv://<service>[/<account>][#<field>]`: `tv://openai`, `tv://github/bot#password`, `tv://github/personal#totp`.
That is the canonical form. For convenience, `typevault://github/bot` and the bare `github/bot` work everywhere too.
No environments, no domains, no group in the name. Fields come from the type:

| Type       | Fields (default first)                                                       |
| ---------- | ---------------------------------------------------------------------------- |
| `password` | password, username, totp, url                                                |
| `api_key`  | key                                                                          |
| `oauth`    | access_token, refresh_token, expires_at, token_url, client_id, client_secret |
| `ssh`      | private_key, public_key                                                      |
| `totp`     | seed                                                                         |
| `note`     | text                                                                         |

Env names are derived: `tv://github/bot#password` becomes `GITHUB_BOT_PASSWORD`. Override the main field's name with `--env`.
In `run`, TOTP fields carry the current code, never the seed. Secret fields are never accepted as `--field` arguments
(they would land in `ps` and shell history): pass them with `--stdin` or `--stdin-json`.

### What `run` loads

A lower group can write entries a higher group reads, so `run` only loads, in bulk, entries from the groups the
caller holds directly. An entry from an included group is loaded only when `--only` names it exactly
(`--only tv://github/bot`, not `--only 'tv://github/*'`). Two entries setting the same variable is an error, and variables that
change how programs load code or route traffic (`PATH`, `LD_*`, `NODE_OPTIONS`, `GIT_*`, `HTTPS_PROXY`, ...) are never set
from the vault. The child never receives `TYPEVAULT_*` variables.

An entry from an included group keeps its `--env` override only when the operator, or a key at least as privileged as
the caller, wrote it; otherwise it gets the derived name. The operator holds no group directly, so the operator's own `run` loads only what `--only` names.

When the same name exists in several groups, the copy in the higher group wins; timestamps never decide. If two
unrelated groups hold it, reads of that name fail until the operator keeps one: `typevault rm <name> --group <g>`.

### References in the environment

`run` also replaces any variable whose whole value is a reference with that field, so you pick the variable name.
Here the scheme is required: a bare `github/bot` stays a plain string.

```sh
DATABASE_URL=tv://postgres/prod#url BOT_TOKEN=tv://github/bot typevault run -- ./deploy.sh
```

A reference names its entry exactly, so it resolves anything your grant reaches, like `--only <name>`. Loader
variables (`PATH`, `NODE_OPTIONS`, ...) are refused, and a reference naming a variable an entry also sets is an error.

## Grants

|                  | Live (default)                | Sealed (`--sealed`)            |
| ---------------- | ----------------------------- | ------------------------------ |
| Needs the daemon | yes                           | no                             |
| Audit            | every read                    | issue time (reads best-effort) |
| TTL / revocation | enforced / instant            | advisory / impossible          |
| Use for          | laptops, containers, typeclaw | CI, one-shot containers        |

A sealed grant can write, within its groups and `--only`, until its certificate expires by the **reader's** clock.
A daemon (every minute) or `typevault doctor --fix` adopts those writes by re-signing them. Writes nobody adopts
before expiry stop being trusted; the operator can still keep them with `typevault doctor --fix --adopt-expired`.

```sh
typevault grant --group member --only 'tv://github/*' --ttl 30m --label ci:deploy
typevault grant ls
typevault grant revoke --label ci:deploy         # also revokes grants derived from it
TYPEVAULT_GRANT=@/run/agent/grant typevault get tv://github/bot
```

`TYPEVAULT_GRANT` takes a live grant (`tvl1.…`), a sealed one (`tvg1:…`) or `@path` to a file holding either.
Without it, the CLI uses local keys (direct mode: the operator, or a launcher with `TYPEVAULT_KEY`).

### Ceilings

Each admin socket (`run/admin-<name>.sock`) may issue grants only up to its ceiling, signed by the operator:

```sh
typevault ceiling set bot member                 # admin-bot.sock can grant member and below
TYPEVAULT_CEILING=bot typevault grant --group member
```

The socket is the caller's identity, so protect it with file permissions or by mounting it only where it belongs.
A capped socket lists and revokes only the grants it issued, and only the uncapped operator socket reads the audit trail.
Processes under one OS user that can reach the same socket share its ceiling; per-session enforcement needs isolation
(typeclaw sandboxes each session and mounts only the agent socket).

## Asking a human for a secret

```sh
typevault request resend --type api_key --reason "send the weekly digest"
```

The daemon serves a one-time page (`TYPEVAULT_PROMPT_PORT`, `TYPEVAULT_PUBLIC_URL` for tunnels). The browser encrypts the
value to the group before submitting, so the plaintext never reaches the server, logs or the model.

## Redaction

- `typevault run` redacts its child's stdout and stderr by default.
- `cmd | typevault redact` scrubs anything your grant has read.
- `typevault scrub <files>` rewrites transcripts in place.
- `typevault get` prints the value on purpose; prefer `run`.

## SDK

The same access, in-process (Bun only):

```ts
import { createClient, parseEntryName } from 'typevault'
import { createAdmin } from 'typevault/admin'
import { createRedactor } from 'typevault/redact'

// A launcher issues a grant within its socket's ceiling...
const grant = await createAdmin({ ceiling: 'bot' }).grant({ groups: ['member'], ttl: '30m', label: 'session:abc' })

// ...and the agent side reads through it (live via the daemon, or sealed in-process).
const vault = await createClient({ grant })
const { fields } = await vault.get(parseEntryName('tv://openai'), 'send the weekly digest')

// Nothing is redacted for you: scrub anything that can reach output.
const redactor = createRedactor(await vault.readValues())
```

`createClient` takes `grant` (default `TYPEVAULT_GRANT`), `dir` and `env`; `dir` (default `TYPEVAULT_DIR`) selects a
global-style vault, and without it the vault is chosen like the CLI's. Without a grant it
refuses unless you pass `direct: true`, which loads this machine's keys into your process; keep that to launchers.
`createAdmin` takes `dir`, `ceiling` and `env`, and offers `grant`, `list` and `revoke`. Both take `global: true` to use
the global vault, like `-g`.

## Operator tasks

```sh
typevault key export member                      # TYPEVAULT_KEY for a CI launcher or remote daemon
typevault key rotate member                      # new generation; lists every secret to rotate at its source
typevault group exclude trusted member           # drop an include (rotates member)
typevault signer add ci-bot <ed25519-public-key> --groups member
typevault import 1password export.1pux --group member
typevault doctor --fix                           # verify signatures, resolve git merges and duplicates
typevault audit --verify
```

Operator key rotation and recovery are manual: back up `keys/operator.key` offline.

## Layout

```
$TYPEVAULT_DIR/
  vault/            # ciphertext only, safe to commit
    entries/        # one signed file per entry, opaque names
    groups/         # wrapped group keys
    groups.json signers.json ceilings.json   # operator-signed
    operator.json
    audit-anchors/  # one file per checkout's audit chain
  keys/             # private keys (0600), never commit
  audit/            # full local audit log
  run/              # sockets, lock, grants, staged transactions, revision high-water marks
  vaults/<id>/keys/ # keys of each project vault, shared by its checkouts
  checkouts/<id>/   # trust.json audit/ run/ of each project checkout

<project>/.typevault/   # a project vault: the same files as vault/, all safe to commit
```

## Git history

Old ciphertext stays in history forever. If a key leaks, rotate the key **and** every secret it could reach.
Removing an entry does not remove it from history.

Every old revision is still validly signed, so each machine remembers the newest revision it has seen of every entry
and manifest, and every entry it deleted, and refuses older or deleted ones restored from history. A fresh clone trusts
what it first sees.

## Known limits

- Redaction is best effort: values shorter than 4 characters, hex or composed encodings (such as HTTP Basic auth) can slip
  through. Prefer `run` over `get`.
- The local audit chain is unkeyed: a process running as the same user can rewrite records since the last anchor.
- Same-user processes that can reach one admin socket share its ceiling; isolate sessions to enforce more.

## License

MIT
