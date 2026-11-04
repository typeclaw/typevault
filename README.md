# TypeVault

**Secrets for agents, not for transcripts.** A CLI-first vault that hands each agent session exactly the secrets its
grant allows. Every read leaves a trail, and values stay out of model context.

[![npm version](https://img.shields.io/npm/v/typevault?color=cb3837&logo=npm)](https://www.npmjs.com/package/typevault) [![MIT license](https://img.shields.io/badge/license-MIT-blue)](#license)

## Grants, not keys: agents never hold the vault

- **Short-lived grants**: an agent gets a grant scoped to tiers, entry patterns and a TTL; a daemon holds the keys, serves values and audits every read
- **Instant revocation**: live grants die the moment you revoke them, along with every grant derived from them
- **Sealed grants for CI**: self-contained grants work with no daemon for one-shot containers and pipelines
- **Ceilings without a human in the loop**: an owner-signed ceiling caps what each admin socket may grant, so an issuer can mint grants unattended but never above its cap

## Tiers are keys: access enforced by cryptography

- **One keypair per tier**: a secret is encrypted to its tier, so reach comes from holding a key, not from a permission check
- **Inclusion**: tiers can include others (`trusted` reaches everything `member` does), and the higher tier's copy wins on name clashes
- **Rotation that tells you what to rotate**: `key rotate` starts a new generation and lists every secret to rotate at its source
- **Reading = using**: if a grant can use a secret it can read it, so put a secret in a tier only if that tier may see it

## Members, not shared keys: your password unlocks your own key

- **One key per member**: each person and machine has its own key, and tier keys are wrapped to members, so sharing a vault never means passing a key or a password around
- **Password + Secret Key**: a person's key is sealed by their password and a random Secret Key kept on their device, so the sealed copy can sit in git and still resist offline guessing
- **Unlock once, agents keep working**: `typevault unlock` hands your key to the daemon for a while; agents read through it without ever seeing a password or a key, and `typevault lock` ends it
- **Machines need no password**: CI and agent hosts join as machine members, each with its own key and only the tiers it needs
- **Rotation on every membership change**: adding or removing a member rotates every tier they reach, so nobody opens history from before they joined

## Git-friendly: commit the vault; no key is stored in the clear

- **A directory of files**: one age-encrypted, signed file per entry, with opaque names; commit `.typevault/` with your project
- **Project and global vaults**: like `bun` and `npm`, commands target the nearest project vault, and `-g` selects the global one
- **Rollback protection**: each checkout remembers the newest revision it has seen, so old ciphertext restored from history is refused
- **Merge repair**: `doctor --fix` verifies signatures and resolves git merges and duplicate entries

## Out of transcripts: values reach programs, not the model

- **`run` injects env vars**: secrets arrive as environment variables, loader variables like `PATH` and `NODE_OPTIONS` are never set from the vault, and the child's output is redacted
- **`tv://` references**: set `DATABASE_URL=tv://postgres/prod#url` and `run` swaps in the value, so you choose the variable name
- **Redaction everywhere**: pipe through `typevault redact` or rewrite saved transcripts in place with `typevault scrub`
- **TOTP done right**: `run` passes the current code, never the seed

## Asking a human: one link, no plaintext on the wire

- **`request`**: an agent asks for a missing secret and gets a one-time URL plus a match code to hand to a human
- **Encrypted in the browser**: the page encrypts the value to the tier before submitting, so tunnels and proxies carry only ciphertext; the daemon decrypts it to check it matches the request, then stores it, and the model never sees the value

## Audit: every read leaves a trail

- **Per-read records**: live grants log every read with its label and stated reason
- **Follow a session**: `audit --label ci:deploy --follow` streams one grant's reads as they happen
- **Verifiable chain**: `audit --verify` checks the hash chain against anchors committed with the vault

## Imports: bring your existing secrets

- **1Password, directly**: import from the 1Password app through its SDK or `op`, with no export file; narrow by vault or tag
- **Everything else**: `.env` files, TypeClaw agent folders, 1Password `.1pux`, Bitwarden, LastPass, KeePass and CSV, each as one transaction into one tier

## SDK: the same access in-process

- **Three entry points**: `typevault` for clients, `typevault/admin` for issuers that mint grants, and `typevault/redact` for scrubbing output
- **Agent skill included**: [`skills/typevault`](./skills/typevault) teaches coding agents to use grants, `run` and references correctly

TypeVault is general-purpose: any agent runtime can use it. [TypeClaw](https://github.com/typeclaw/typeclaw) is its first consumer, sandboxing each session and mounting only the agent socket.

## Install

```sh
bun add -g typevault
```

Requires Bun ≥ 1.3.

## Quickstart

```sh
typevault init                                   # creates .typevault/ here with a `default` tier; -g for global
                                                 # (the first time, also your identity: a password and a Secret Key)
typevault unlock                                 # once per session (8h by default); your agents use it too

# With one tier, set needs no --tier
printf '%s' "$OPENAI_KEY" | typevault set tv://openai --preset api_key --stdin
typevault set tv://anthropic --preset api_key        # from a terminal: type it in a one-time local page (--web)
typevault set tv://github/bot --preset password --field username=bot --stdin < password.txt
echo '{"access_token":"…","refresh_token":"…"}' | typevault set tv://google --preset oauth --stdin

# Split reach once agents need different access
typevault tier add trusted
typevault tier include trusted default          # trusted reaches everything default reaches
printf '%s' "$STRIPE_KEY" | typevault set tv://stripe --preset api_key --tier trusted --stdin

# Hand an agent a grant instead of a key (served by your unlocked session's daemon)
export TYPEVAULT_GRANT=$(typevault grant --tier default --label session:abc)

typevault whoami                                 # live grant, sealed grant, unlocked session or machine key
typevault ls
typevault run -- psql                            # secrets arrive as env vars; output is redacted
typevault run --only tv://github/bot -- sh -c 'agent-browser fill @e3 "$GITHUB_BOT_PASSWORD"'
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

A project vault holds only ciphertext, wrapped keys and signed manifests, so commit `.typevault/` as is. Each checkout
keeps its own trust pin, audit log and daemon under `~/.config/typevault/checkouts/<id>/`, keyed by the checkout's
path. A collaborator gets access by joining as a member, or with a grant, as with the global vault.

To start over, delete `.typevault/` and run `typevault init` again. `init` stops this checkout's daemon and clears its
runtime state (grants, session, revision marks), which belonged to the old vault, and pins the new owner key. The pin
stays keyed by path, so a vault whose `owner.json` is swapped through git is still refused: only `init` re-pins.

## Members and unlocking

```sh
typevault init                                   # the first time: choose a password, save the printed Secret Key
typevault unlock --for 8h                        # your key goes to the daemon until then
typevault lock                                   # ends the session now
typevault passwd                                 # new password; your key and every vault stay the same

# Someone joins (in their clone), then an owner adds them with the line it printed
typevault join                                   # prints: typevault member add bob tvp1:... --tier <tiers>
typevault member add bob tvp1:... --tier default # rotates every tier bob reaches
typevault member rm bob                          # rotates again; lists what bob could read
typevault member ls

# A machine (CI, an agent host): no password, its own key
typevault join --machine --name ci
```

Each device has one identity, `~/.config/typevault/identity.json` (0600), used in every vault it joins. A person's
holds their Secret Key and their member key sealed by password and Secret Key; `init` and `join` also commit that
sealed copy to `members/<name>.key`, so on a new device `typevault identity restore <name>` needs only the Secret Key
and the password. Keep the Secret Key somewhere safe: `typevault identity export --to 1password --vault Backup`. A
machine's identity holds its key directly, or the key comes from `TYPEVAULT_KEY`.

`unlock` starts a daemon that holds your key until `--for` runs out (8h by default) or `typevault lock`. The vault counts
as unlocked only while that session is running: a daemon without one (a machine member's, or one left from an older
release) is stopped and replaced, once the password checks out. Without a grant, your CLI and your agents read through
the session. Agents never see the password or the key, and live grants you issue work only while it runs.

While a person's vault is locked, an agent's command fails with `the vault is locked: ask a human to run typevault
unlock`; in a terminal, the command asks for the password and unlocks on the spot. Owner commands (`tier`, `member`,
`key rotate`, ...) ask for the password every time, because only they open the owner key. Scripts pass passwords on
stdin with `--vault-password-stdin`, one per line. Removing an owner member isn't supported yet: every entry is also
sealed to the owner key, which can't be rotated yet.

## Naming

`tv://<service>[/<account>][#<field>]`: `tv://openai`, `tv://github/bot#password`, `tv://github/personal#totp`.
That is the canonical form. For convenience, `typevault://github/bot` and the bare `github/bot` work everywhere too.
No environments, no domains, no tier in the name.

Each field stores its own type: `secret` (sensitive string), `text` (public string), `totp` (seed or otpauth URI), or `oauth` (an object with `access_token` and optional `refresh_token`, `expires_at`, `token_url`, `client_id`, `client_secret`). OAuth reads yield the access token and refresh expired credentials when possible.

Presets only pre-fill fields at write time; no preset is stored:

| Preset     | Fields                                                  | Single stdin input |
| ---------- | ------------------------------------------------------- | ------------------ |
| `password` | username(text), password(secret), totp(totp), url(text) | password           |
| `api_key`  | $default(secret)                                        | $default           |
| `oauth`    | $default(oauth)                                         | JSON via --stdin   |
| `ssh`      | private_key(secret), public_key(text)                   | private_key        |
| `totp`     | $default(totp)                                          | $default           |
| `note`     | $default(secret)                                        | $default           |

Without a preset, `set --stdin` stores `$default` (or overwrites the existing default field). Bare references choose `$default`, else the only field, else fail and list the fields. A login with several fields needs `#password` or another selector. `#$default` is rejected; use the bare name. OAuth parts use `#field.refresh_token`, or `#refresh_token` for the default field; an actual field with that name wins.

Field names keep their case, with up to 64 characters and no `=`, controls or surrounding spaces. Names starting with `$` are reserved except `$default`:

```sh
echo '{"$default":"…","Webhook Secret":"…"}' | typevault set tv://stripe --preset api_key --stdin-json
typevault get 'tv://stripe#Webhook Secret' --reveal   # an exact match, else the one field equal ignoring case
```

Env names are derived: `tv://github/bot#password` becomes `GITHUB_BOT_PASSWORD` and `tv://stripe#Webhook Secret`
becomes `STRIPE_WEBHOOK_SECRET`. A field with no Latin letter or digit gets no variable; reach it with a reference.
The `$default` field uses the entry name alone: `tv://openai` becomes `OPENAI`. Override the default field's variable with `--env`.
In `run`, TOTP fields carry the current code; `otp [ref]` prints a selected TOTP field, the default when typed TOTP, or the only TOTP field. `get` keeps the raw stored seed.
`--field k=v` always writes a `text` field. Pass secrets through stdin or the browser. `--stdin-json` accepts strings or full `{"type":"secret","value":"…"}` objects. Updates merge existing fields and preserve their types; `--replace` replaces all fields.

### What `run` loads

A lower tier can write entries a higher tier reads, so `run` only loads, in bulk, entries from the tiers the
caller holds directly. An entry from an included tier is loaded only when `--only` names it exactly
(`--only tv://github/bot`, not `--only 'tv://github/*'`). Two entries setting the same variable is an error, and variables that
change how programs load code or route traffic (`PATH`, `LD_*`, `NODE_OPTIONS`, `GIT_*`, `HTTPS_PROXY`, ...) are never set
from the vault. The child never receives `TYPEVAULT_*` variables.

An entry from an included tier keeps its `--env` override only when the owner, or a key at least as privileged as
the caller, wrote it; otherwise it gets the derived name. The owner holds no tier directly, so the owner's own `run` loads only what `--only` names.

When the same name exists in several tiers, the copy in the higher tier wins; timestamps never decide. If two
unrelated tiers hold it, reads of that name fail until the owner keeps one: `typevault rm <name> --tier <g>`.

### References in the environment

`run` also replaces any variable whose whole value is a reference with that field, so you pick the variable name.
Here the scheme is required: a bare `github/bot` stays a plain string.

```sh
DATABASE_URL=tv://postgres/prod#url BOT_TOKEN=tv://github/bot#password typevault run -- ./deploy.sh
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

A sealed grant can write, within its tiers and `--only`, until its certificate expires by the **reader's** clock.
A daemon (every minute) or `typevault doctor --fix` adopts those writes by re-signing them. Writes nobody adopts
before expiry stop being trusted; the owner can still keep them with `typevault doctor --fix --adopt-expired`.

```sh
typevault grant --tier member --only 'tv://github/*' --ttl 30m --label ci:deploy
typevault grant ls
typevault grant revoke --label ci:deploy         # also revokes grants derived from it
TYPEVAULT_GRANT=@/run/agent/grant typevault run -- ./deploy.sh
```

`TYPEVAULT_GRANT` takes a live grant (`tvl1.…`), a sealed one (`tvg1:…`) or `@path` to a file holding a sealed one.
Without it, a person's CLI reads through their unlocked session, and a machine member reads with its own key (direct
mode).

### Ceilings

Each admin socket (`run/admin-<name>.sock`) may issue grants only up to its ceiling, signed by the owner:

```sh
typevault ceiling set bot member                 # admin-bot.sock can grant member and below
TYPEVAULT_CEILING=bot typevault grant --tier member
```

The socket is the caller's identity, so protect it with file permissions or by mounting it only where it belongs.
A capped socket lists and revokes only the grants it issued, and only the uncapped owner socket reads the audit trail.
Processes under one OS user that can reach the same socket share its ceiling; per-session enforcement needs isolation
(typeclaw sandboxes each session and mounts only the agent socket).

## Asking a human for a secret

```sh
typevault request resend --preset api_key --reason "send the weekly digest"
```

It prints a one-time URL and a match code to give the human, then waits until they submit. The daemon serves the page
(`TYPEVAULT_PROMPT_PORT`, `TYPEVAULT_PUBLIC_URL` for tunnels). The browser encrypts the value to the tier before
submitting, so anything between the browser and the daemon (tunnels, proxies) sees only ciphertext. The trusted daemon
decrypts the submission to check that it is exactly the requested entry, then re-encrypts, signs and stores it. The value
is never written to logs or shown to the model.

## Redaction

- `typevault run` redacts its child's stdout and stderr by default.
- `cmd | typevault redact` scrubs anything your grant has read.
- `typevault scrub <files>` rewrites transcripts in place.
- `typevault get` prints `text` fields but refuses other field types without `--reveal`;
  `--json` prints `{field: {type, value}}` with non-text values redacted. Prefer `run`.

## SDK

The same access, in-process (Bun only):

```ts
import { createClient, parseEntryName } from 'typevault'
import { createAdmin } from 'typevault/admin'
import { createRedactor } from 'typevault/redact'

// An issuer issues a grant within its socket's ceiling...
const grant = await createAdmin({ ceiling: 'bot' }).grant({ tiers: ['member'], ttl: '30m', label: 'session:abc' })

// ...and the agent side reads through it (live via the daemon, or sealed in-process).
const vault = await createClient({ grant })
const { fields } = await vault.get(parseEntryName('tv://openai'), 'send the weekly digest')

// Nothing is redacted for you: scrub anything that can reach output.
const redactor = createRedactor(await vault.readValues())
```

`createClient` takes `grant` (default `TYPEVAULT_GRANT`), `dir` and `env`; `dir` (default `TYPEVAULT_DIR`) selects a
global-style vault, and without it the vault is chosen like the CLI's. Without a grant it
refuses unless you pass `direct: true`, which reads through the unlocked session, or loads a machine member's key
into your process; keep that to issuers.
`createAdmin` takes `dir`, `ceiling` and `env`, and offers `grant`, `list` and `revoke`. Both take `global: true` to use
the global vault, like `-g`.

## Owner tasks

```sh
typevault identity export --to 1password --vault Backup   # your Secret Key (or a machine's key)
typevault key rotate member                      # new generation; lists every secret to rotate at its source
typevault tier exclude trusted member           # drop an include (rotates member)
typevault signer add ci-bot <ed25519-public-key> --tiers member
typevault import 1password export.1pux --tier member
typevault import 1password --account Acme --tier member   # straight from the 1Password app
typevault doctor --fix                           # verify signatures, resolve git merges and duplicates
typevault audit --verify
typevault audit --label ci:deploy --follow       # stream one grant's reads
typevault daemon status                          # also: daemon start | stop | run (foreground)
                                                 # a background daemon writes to run/daemon.log; a failed start quotes it.
                                                 # it holds run/daemon.lock until its cleanup is done, so a stop waits for that
```

`tier`, `ceiling` and `signer` each also have `ls` and `rm`.

The owner key is never stored in the clear: it exists only wrapped to owner members, so an owner's password and
Secret Key are the recovery path. Owner key rotation is not supported yet.

`identity export --to 1password` uses the `op` CLI when installed, else the 1Password app (`--via sdk|op` to choose;
`--account` is required for the app or when several `op` accounts are signed in). The Secret Key, or a machine's key,
goes in the item's `credential` field, so a machine can run with
`TYPEVAULT_KEY="op://Infra/TypeVault identity ci/credential"` under `op run`. An existing item with the same title is
refused unless `--replace`, which archives it after storing the new one.

### Importing from 1Password

Without a path, `import 1password` reads the app directly; nothing is exported or piped. Access is approved in
1Password (Touch ID or your password): the SDK asks on every run, while `op` reuses an approval within the same
terminal session until 10 minutes pass without use.

```sh
typevault import 1password --account Acme --tier member            # 1Password SDK (default); turn on Settings > Developer > Integrate with other apps
typevault import 1password --via op --vault Work --tier member      # the 1Password CLI (`op`), signed in through the app
typevault import 1password --account Acme --tag myproject-typevault --tier member   # only items tagged in 1Password
```

`--account` is the account name shown in the app's sidebar (or its UUID); `--via op` uses `op`'s default account
unless you pass one. `--vault` limits the import to that vault and `--tag` to items carrying that tag, so tagging items
in 1Password picks what agents may reach; re-run the import after tagging more. Each of `--account`, `--vault` and
`--tag` can be repeated: an item matches any of a flag's values and must match every flag given, so
`--account Work --account Home --vault Infra --tag agents` reads both accounts' `Infra` vaults (a vault only one
account has is fine) for items tagged `agents`. To import only some fields of an item,
tag it `<tag>/<field>` instead (`myproject-typevault/Account Id`, one tag per field): the name matches the field as
TypeVault stores it (`password`, `totp`, or a custom field's label), ignoring case. The plain tag wins when an item
carries both, and the `<tag>/...` tags aren't copied into the vault.
Logins, passwords, secure notes, API credentials and SSH keys are imported as `tv://<title>/<vault>`; other categories
and archived items are skipped.

### Importing from files

Every import runs as one transaction into one tier:

```sh
typevault import dotenv .env --tier member
typevault import typeclaw ./agent --tier member            # the .env inside a typeclaw directory
typevault import 1password export.1pux --tier member
typevault import bitwarden export.json --tier member
typevault import lastpass export.csv --tier member
typevault import keepass vault.kdbx --password-stdin --tier member < kdbx-password.txt
typevault import csv secrets.csv --tier member
```

## Environment

| Variable                                        | Effect                                                                                                         |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `TYPEVAULT_GRANT`                               | The grant this process uses; unset means the unlocked session, or direct mode for a machine                    |
| `TYPEVAULT_GLOBAL`                              | Same as `-g`                                                                                                   |
| `TYPEVAULT_DIR`                                 | Use the vault kept whole at this path; the global one is `$XDG_CONFIG_HOME/typevault` or `~/.config/typevault` |
| `TYPEVAULT_KEY`                                 | A machine member's key, instead of the identity file (`identity export`)                                       |
| `TYPEVAULT_TIER`                                | Default tier for `set`                                                                                         |
| `TYPEVAULT_CEILING`                             | Admin socket to grant through (default `default`)                                                              |
| `TYPEVAULT_OWNER`                               | Pin the owner key instead of trusting it on first use                                                          |
| `TYPEVAULT_PROMPT_PORT`, `TYPEVAULT_PUBLIC_URL` | Where the daemon serves `request` pages                                                                        |

## Layout

```
$TYPEVAULT_DIR/
  identity.json     # this device's identity (0600), never commit
  trust.json        # the owner key this machine trusts
  vault/            # ciphertext and wrapped keys only, safe to commit
    entries/        # one signed file per entry, opaque names
    tiers/          # tier keys wrapped to the owner, including tiers and members
    owner/          # the owner key wrapped to each owner member
    members/        # each person's member key, sealed by their password and Secret Key
    tiers.json members.json signers.json ceilings.json   # owner-signed
    owner.json
    audit-anchors/  # one file per checkout's audit chain
  audit/            # full local audit log
  run/              # sockets, locks, grants, session token, daemon.log, staged transactions, revision marks
  checkouts/<id>/   # trust.json audit/ run/ of each project checkout

<project>/.typevault/   # a project vault: the same files as vault/, all safe to commit
```

## Git history

Old ciphertext stays in history forever. If a key leaks, rotate the key **and** every secret it could reach.
Removing an entry does not remove it from history. Adding a member rotates every tier they reach first, so their key
opens none of the ciphertext from before they joined; removing one rotates again and lists what they could read.

Every old revision is still validly signed, so each machine remembers the newest revision it has seen of every entry
and manifest, and every entry it deleted, and refuses older or deleted ones restored from history. A fresh clone trusts
what it first sees.

## Known limits

- Redaction is best effort: values shorter than 4 characters, hex or composed encodings (such as HTTP Basic auth) can slip
  through. Prefer `run` over `get`.
- The local audit chain is unkeyed: a process running as the same user can rewrite records since the last anchor.
- Same-user processes that can reach one admin socket share its ceiling; isolate sessions to enforce more.

## Development

```sh
git clone https://github.com/typeclaw/typevault
cd typevault
bun install
bun test
```

Pre-commit checks (all must pass):

```sh
bun run typecheck
bun run lint
bun run format:check
```

## Acknowledgments

- **Encryption** is [age](https://age-encryption.org), via [age-encryption](https://github.com/FiloSottile/typage) by [@FiloSottile](https://github.com/FiloSottile).
- **Signatures and hashing** come from [@noble/curves](https://github.com/paulmillr/noble-curves) and [@noble/hashes](https://github.com/paulmillr/noble-hashes) by [@paulmillr](https://github.com/paulmillr).

## License

MIT
