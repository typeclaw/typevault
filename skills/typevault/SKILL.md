---
name: typevault
description: Use secrets from a typevault vault without leaking them into transcripts. Use when a task needs an API key, password, token, OAuth credential, SSH key or TOTP code, when a project has a `.typevault/` directory or `TYPEVAULT_GRANT` is set, or when the user mentions typevault, storing a secret, granting an agent access, or redacting secrets from output.
allowed-tools: Bash(typevault:*), Bash(bunx typevault:*)
---

# typevault

A CLI-first secrets vault for agents. Secrets are age-encrypted files in `.typevault/` (per project) or
`~/.config/typevault` (global, `-g`). Agents reach them through a grant. With a live grant every read is audited; a sealed grant is audited
when issued, and its reads only best effort.

Install: `bun add -g typevault`

## Rules

- **Never print a secret.** Use `typevault run` so values go into the child's env and its output is redacted. `get`
  and `otp` put the value in your transcript; use them only when nothing else works.
- **Never put a secret on the command line.** Pass it on stdin (`--stdin`, `--stdin-json`); `--field` takes only
  `username`, `url`, `token_url`, `client_id`, `expires_at` and `public_key`.
- **Need a secret you don't have? Ask the human through `typevault request`**, not in chat. The value never reaches
  the model.
- **Always give a `--reason`.** It is written to the audit trail.
- Don't guess the vault: commands use the nearest `.typevault/` and fail outside a project. Add `-g` (before `--`)
  only when the user means the global vault.

## Look around

```sh
typevault whoami                 # how this process reaches the vault (grant or local keys) and which vault
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
- `run` loads every entry from the groups you hold directly. An entry from an included group loads only when `--only`
  names it exactly (no globs). In direct mode (no grant) the operator holds no group directly, so name what you need
  with `--only`.
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
existing env var or a file you don't open. `--group` defaults to your grant's group (or the vault's only group). Add `--env NAME` to choose the main field's env
name in `run`.

## Ask a human

```sh
typevault request resend --type api_key --reason "send the weekly digest"
```

Prints a one-time URL and a match code; give both to the user, then the command waits until they submit. Their
browser encrypts the value before submitting it, and it is stored as the named entry. Needs a live grant (the daemon
serves the page).

## Import (operator)

Run these only when the user asks; they write with local keys, not a grant.

```sh
typevault import 1password --account Acme --group default             # straight from the 1Password app; the user approves in 1Password
typevault import 1password --via op --vault Work --tag agents --group default
typevault import dotenv .env --group default                           # also: typeclaw, 1password (.1pux), bitwarden, lastpass, keepass, csv
```

KeePass reads its password from `--password-stdin`.

## Grants (operator or launcher)

An agent should hold a grant, not keys. Without `TYPEVAULT_GRANT`, the CLI uses local keys (direct mode).

`typevault grant` prints the token, and a token is a credential: a sealed one carries the secrets themselves and can't
be revoked. Never let it reach output; capture it into a variable, or a sealed one into a `0600` file.

```sh
typevault init                                         # new project vault with a `default` group
export TYPEVAULT_GRANT=$(typevault grant --group default --ttl 1h --label session:abc)
DEPLOY_GRANT=$(typevault grant --group member --only 'tv://github/*' --ttl 30m --label ci:deploy)
(umask 077; typevault grant --group member --sealed --label ci:build > build.grant)   # offline, for CI; no revocation
TYPEVAULT_GRANT=@build.grant typevault ls
typevault grant ls                                     # metadata only, no tokens
typevault grant revoke --label ci:deploy
```

`TYPEVAULT_GRANT` takes a live grant (`tvl1.`), a sealed one (`tvg1:`) or `@path` to a file holding a sealed one. Live
grants start the daemon automatically.

## Troubleshooting

- **No vault found**: you're outside a project. Run `typevault init` there, or use `-g` for the global vault.
- **Entry not listed**: your grant doesn't reach its group. Ask the operator for a grant that does; don't work around
  it.
- **Same variable set by two entries**: narrow with `--only`.
- **Name held by unrelated groups**: the operator settles it with `typevault rm <name> --group <g>`.
- **Signature or merge problems after a git pull**: `typevault doctor --fix` (operator).
- **Daemon trouble with a live grant**: check `typevault daemon status`, then ask the operator. Don't stop the daemon
  yourself: restarting it needs keys a grant doesn't carry.

Run `typevault <command> --help` for every flag.
