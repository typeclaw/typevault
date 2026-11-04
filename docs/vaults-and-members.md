# Vaults and members

Where vaults live, how people and machines join, and what git history keeps.

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

## Git history

Old ciphertext stays in history forever. If a key leaks, rotate the key **and** every secret it could reach.
Removing an entry does not remove it from history. Adding a member rotates every tier they reach first, so their key
opens none of the ciphertext from before they joined; removing one rotates again and lists what they could read.

Every old revision is still validly signed, so each machine remembers the newest revision it has seen of every entry
and manifest, and every entry it deleted, and refuses older or deleted ones restored from history. A fresh clone trusts
what it first sees.

---

Back to the [README](../README.md).
