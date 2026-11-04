---
name: typevault
description: Use secrets from a TypeVault vault without leaking them into transcripts. Use when a task needs an API key, password, token, OAuth credential, SSH key or TOTP code, when a project has a `.typevault/` directory or `TYPEVAULT_GRANT` is set, or when the user mentions TypeVault, storing a secret, granting an agent access, or redacting secrets from output.
allowed-tools: Bash(typevault:*), Bash(bunx typevault:*)
---

# TypeVault

A CLI-first secrets vault for agents. Secrets are age-encrypted files in `.typevault/` (per project) or
`~/.config/typevault` (global, `-g`). Agents reach them through a grant. With a live grant every read is audited; a sealed grant is audited
when issued, and its reads only best effort.

Install: `bun add -g typevault`

## Rules

- **Never print a secret.** Use `typevault run` so values go into the child's env and its output is redacted. `get`
  refuses secret fields unless you pass `--reveal`. `--reveal` and `otp` put the value in your transcript; use
  them only when nothing else works.
- **Never put a secret on the command line.** Pass it on stdin (`--stdin`, `--stdin-json`); `--field` takes only
  `username`, `url`, `token_url`, `client_id`, `expires_at` and `public_key`.
- **Need a secret you don't have? Ask the human through `typevault request`**, not in chat. The value never reaches
  the model.
- **Always give a `--reason`.** It is written to the audit trail.
- Don't guess the vault: commands use the nearest `.typevault/` and fail outside a project. Add `-g` (before `--`)
  only when the user means the global vault.

## Look around

```sh
typevault whoami                 # how this process reaches the vault (grant, unlocked session or machine key)
typevault ls                     # entries your grant reaches
typevault ls --json
```

Entries are named `tv://<service>[/<account>][#<field>]`: `tv://openai`, `tv://github/bot#password` (`github/bot`
works too). Without `#field`, the type's main field
is used. The type suggests fields, and an entry may hold any other (`tv://stripe#Webhook Secret`; quote it in the
shell). Field names keep their case; a ref matches exactly, else the one field equal ignoring case.

| Type       | Fields (main first)                                                          |
| ---------- | ---------------------------------------------------------------------------- |
| `password` | password, username, totp, url                                                |
| `api_key`  | key                                                                          |
| `oauth`    | access_token, refresh_token, expires_at, token_url, client_id, client_secret |
| `ssh`      | private_key, public_key                                                      |
| `totp`     | seed                                                                         |
| `note`     | text                                                                         |

## Use secrets

```sh
typevault run --reason "run migrations" -- psql
typevault run --only tv://github/bot --reason "log in to GitHub" -- sh -c 'agent-browser fill @e3 "$GITHUB_BOT_PASSWORD"'
typevault run --only 'tv://openai,tv://stripe' -- bun run deploy
```

- Env names are derived from the name: `tv://github/bot#password` -> `GITHUB_BOT_PASSWORD`, `tv://openai` -> `OPENAI_KEY`,
  `tv://stripe#Webhook Secret` -> `STRIPE_WEBHOOK_SECRET`, unless the entry sets `--env`. To pick the name yourself, set the variable to a reference:
  `DATABASE_URL=tv://postgres/prod#url typevault run -- ...` (the scheme is required here).
- Write `$VAR` references in single quotes or as arguments the child expands, so your shell doesn't expand them
  first: `typevault run -- sh -c 'curl -H "Authorization: Bearer $OPENAI_KEY" ...'`.
- TOTP fields hold the current code, never the seed.
- `run` loads every entry from the tiers you hold directly. An entry from an included tier loads only when `--only`
  names it exactly (no globs). Without a grant, a person's session loads only the tiers that member holds
  directly (an owner holds none), so name what you need with `--only`.
- Variables like `PATH`, `LD_*`, `NODE_OPTIONS`, `GIT_*`, `HTTPS_PROXY` are never set from the vault, and the child
  never sees `TYPEVAULT_*`.

When a value must reach output you control:

```sh
some-command | typevault redact            # replace every secret your grant has read
typevault scrub transcript.jsonl           # rewrite files in place
```

Redaction is best effort: values under 4 characters, hex or composed encodings (HTTP Basic auth) can slip through.

## Store secrets

```sh
printf '%s' "$VALUE" | typevault set tv://openai --type api_key --stdin
typevault set tv://github/bot --type password --field username=bot --stdin < password.txt
typevault set tv://google --type oauth --stdin-json < oauth.json   # a file the human wrote; don't read it
# custom fields go in the same JSON: {"key":"...","Webhook Secret":"..."}
typevault mv tv://github/bot tv://github/ci
typevault rm tv://github/ci
```

Never type a secret value into a command, even piped: the command text lands in your transcript. Read it from an
existing env var or a file you don't open. `--tier` defaults to your grant's tier (or the vault's only tier). Add `--env NAME` to choose the main field's env
name in `run`.

## Ask a human

```sh
typevault request resend --type api_key --reason "send the weekly digest"
```

Prints a one-time URL and a match code; give both to the user, then the command waits until they submit. Their
browser encrypts the value before submitting it, and it is stored as the named entry. Needs a live grant (the daemon
serves the page).

## Import (owner)

Run these only when the user asks; they open the owner's key, so a person types their password.

```sh
typevault import 1password --account Acme --tier default             # straight from the 1Password app; the user approves in 1Password
typevault import 1password --via op --vault Work --tag agents --tier default   # items tagged agents/<field> import only that field
# --account, --vault and --tag repeat: any value of a flag matches, every flag must match
typevault import dotenv .env --tier default                           # also: typeclaw, 1password (.1pux), bitwarden, lastpass, keepass, csv
```

KeePass reads its password from `--password-stdin`.

## Grants (owner or issuer)

An agent should hold a grant, not keys. Without `TYPEVAULT_GRANT`, the CLI reads through the user's unlocked session,
or with a machine member's own key.

`typevault grant` prints the token, and a token is a credential: a sealed one carries the secrets themselves and can't
be revoked. Never let it reach output; capture it into a variable, or a sealed one into a `0600` file.

```sh
typevault init                                         # new project vault with a `default` tier
export TYPEVAULT_GRANT=$(typevault grant --tier default --ttl 1h --label session:abc)
DEPLOY_GRANT=$(typevault grant --tier member --only 'tv://github/*' --ttl 30m --label ci:deploy)
(umask 077; typevault grant --tier member --sealed --label ci:build > build.grant)   # offline, for CI; no revocation
TYPEVAULT_GRANT=@build.grant typevault ls
typevault grant ls                                     # metadata only, no tokens
typevault grant revoke --label ci:deploy
```

`TYPEVAULT_GRANT` takes a live grant (`tvl1.`), a sealed one (`tvg1:`) or `@path` to a file holding a sealed one. Live
grants go through the daemon: for a person's vault that is their unlocked session, so a live grant stops working when
they lock it; a machine member's daemon starts on its own.

## Troubleshooting

- **No vault found**: you're outside a project. Run `typevault init` there, or use `-g` for the global vault.
- **The vault is locked**: ask the user to run `typevault unlock` in their terminal. Never ask for their password,
  and never pipe one with `--vault-password-stdin`.
- **Entry not listed**: your grant doesn't reach its tier. Ask the owner for a grant that does; don't work around
  it.
- **Same variable set by two entries**: narrow with `--only`.
- **Name held by unrelated tiers**: the owner settles it with `typevault rm <name> --tier <g>`.
- **Signature or merge problems after a git pull**: `typevault doctor --fix` (owner).
- **Daemon trouble with a live grant**: check `typevault daemon status`, then ask the owner. Don't stop the daemon
  yourself: restarting it needs keys a grant doesn't carry.
- **`the typevault daemon did not start: ...`**: the message quotes the daemon's first line and names
  `run/daemon.log`. Show the user both; don't delete runtime state yourself.

Run `typevault <command> --help` for every flag.
