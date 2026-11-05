# Entries and `run`

How entries are named and typed, what `run` loads, and how output is redacted.

## Writing entries

```sh
printf '%s' "$OPENAI_KEY" | typevault set typevault://openai --preset api_key --stdin
typevault set typevault://anthropic --preset api_key        # from a terminal: type it in a one-time local page (--web)
typevault set typevault://github/bot --preset password --field username=bot --stdin < password.txt
echo '{"access_token":"…","refresh_token":"…"}' | typevault set typevault://google --preset oauth --stdin
printf '%s' "$STRIPE_KEY" | typevault set typevault://stripe --preset api_key --tier trusted --stdin
```

## Naming

`typevault://<service>[/<account>][#<field>]`: `typevault://openai`, `typevault://github/bot#password`, `typevault://github/personal#totp`.
That is the canonical form. For convenience, the bare `github/bot` works everywhere too.
Each segment is letters and digits of any script with `@`, `+`, and `-` or `.` between them
(`typevault://국민은행/법인`, `typevault://github/dev@example.com`), stored lowercase and NFC.
Latin mixes only with Chinese, Japanese or Korean in one segment, so a lookalike such as a Cyrillic `а` in `github` is refused.
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
echo '{"$default":"…","Webhook Secret":"…"}' | typevault set typevault://stripe --preset api_key --stdin-json
typevault get 'typevault://stripe#Webhook Secret' --reveal   # an exact match, else the one field equal ignoring case
```

Env names are derived: `typevault://github/bot#password` becomes `GITHUB_BOT_PASSWORD` and `typevault://stripe#Webhook Secret`
becomes `STRIPE_WEBHOOK_SECRET`. A field with no Latin letter or digit gets no variable; reach it with a reference.
The `$default` field uses the entry name alone: `typevault://openai` becomes `OPENAI`. An entry whose name has a letter
outside Latin gets no variables at all; reach its fields with references. Override the default field's variable with `--env`.
In `run`, TOTP fields carry the current code; `otp [ref]` prints a selected TOTP field, the default when typed TOTP, or the only TOTP field. `get` keeps the raw stored seed.
`--field k=v` always writes a `text` field. Pass secrets through stdin or the browser. `--stdin-json` accepts strings or full `{"type":"secret","value":"…"}` objects. Updates merge existing fields and preserve their types; `--replace` replaces all fields.

### What `run` loads

A lower tier can write entries a higher tier reads, so `run` only loads, in bulk, entries from the tiers the
caller holds directly. An entry from an included tier is loaded only when `--only` names it exactly
(`--only typevault://github/bot`, not `--only 'typevault://github/*'`). Two entries setting the same variable is an error, and variables that
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
DATABASE_URL=typevault://postgres/prod#url BOT_TOKEN=typevault://github/bot#password typevault run -- ./deploy.sh
```

A reference names its entry exactly, so it resolves anything your grant reaches, like `--only <name>`. Loader
variables (`PATH`, `NODE_OPTIONS`, ...) are refused, and a reference naming a variable an entry also sets is an error.

## Redaction

- `typevault run` redacts its child's stdout and stderr by default.
- `cmd | typevault redact` scrubs anything your grant has read.
- `typevault scrub <files>` rewrites transcripts in place.
- `typevault get` prints `text` fields but refuses other field types without `--reveal`;
  `--json` prints `{field: {type, value}}` with non-text values redacted. Prefer `run`.

`redact` and `scrub` need known values: use the same active grant that read the secrets. A revoked or expired live
grant is refused; a new grant with no read history also fails instead of reporting a clean transcript. Neither command
recovers another grant's history or broadens its access. Values shorter than four Unicode characters are not matched;
if no matchable values are available, the commands fail.

`scrub` preserves bytes outside matches and refuses symbolic links; pass the target's path explicitly. Each failing
path is reported with its reason, and the remaining files are still processed. Any failure makes the command exit
nonzero. Use `typevault scrub -- -name.log` for filenames beginning with `-`.

---

Back to the [README](../README.md).
