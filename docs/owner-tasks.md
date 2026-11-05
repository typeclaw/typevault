# Owner tasks and imports

Rotation, signers, audit, identity backup, and importing existing secrets.

## Owner tasks

```sh
typevault identity export --to 1password --vault Backup   # your Secret Key (or a machine's key)
typevault key rotate member                      # rotates every reachable tier; lists secrets to rotate at source
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

`key rotate <tier>` gives that tier and every tier it includes, transitively, a new key generation in one transaction.
It lists every secret those keys could reach and flags each for rotation. Rotate each listed secret at its source,
then re-set it in TypeVault to clear the flag. Old keys can still decrypt historical ciphertext and previously exposed
values; changing tier keys cannot revoke those values at their source.

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
Logins, passwords, secure notes, API credentials and SSH keys are imported as `typevault://<title>/<username>`, or
`typevault://<title>` when the item has no username (`GitHub` signed in as `dev@example.com` becomes
`typevault://github/dev@example.com`); a name already taken in the same import gets a `-2` suffix. Other categories
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

Re-running an import updates what it imported before. 1Password, Bitwarden and KeePass items are recognized by
their id, so an item renamed there renames its entry rather than adding a second one; the other formats match by
name. An import never overwrites an entry another item was imported as: it stops with a conflict, and nothing is
written, until you rename or remove that entry.

---

Back to the [README](../README.md).
