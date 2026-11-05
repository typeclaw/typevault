# Vaults and members

Where vaults live, how people and machines join, and what git history keeps.

## Project and global vaults

Like `bun` and `npm`, every command works on the project unless you pass `-g`:

```sh
typevault ls                                     # the nearest .typevault/ up from the working directory
typevault -g ls                                  # the global vault in ~/.typevault
```

Without `-g`, a command run outside any project fails instead of falling back to the global vault, so a secret never
lands in the wrong one. `-g` goes before `--` in `run`; `TYPEVAULT_GLOBAL=1` does the same, and an explicit
`TYPEVAULT_DIR` always selects the vault at that path as the global one. `~/.typevault` is never taken for a project
vault, even from a directory inside your home.

A project vault holds only ciphertext, wrapped keys and signed manifests, so commit `.typevault/` as is. Each checkout
keeps its own trust pin, audit log and daemon under `~/.config/typevault/checkouts/<id>/`, keyed by the checkout's
path, unless you choose the directory (below). A collaborator gets access by joining as a member, or with a grant, as with the global vault. The global vault is laid
out the same way, so `~/.typevault` can be a git repository of its own, synced between your devices.

To start over, delete `.typevault/` and run `typevault init` again. `init` stops this checkout's daemon and clears its
runtime state (grants, session, revision marks), which belonged to the old vault, and pins the new owner key. The pin
stays keyed by path, so a vault whose `owner.json` is swapped through git is still refused: only `init` re-pins.

### Private state in a directory you choose

`TYPEVAULT_STATE_DIR` (SDK: `stateDir`) puts a vault's private state (trust pin, audit log, `run/`) in that directory
instead of `checkouts/<id>/`. Every opener given the same state directory acts as one checkout, whatever path or home it
reaches the vault through, so a folder carrying both the vault and its state can move or be mounted elsewhere and keep
its trust pin, rollback protection and audit chain. Its audit anchors are named by the vault's owner key, not by host or path, so a
deleted audit log still fails against them. Give each vault its own state directory, and keep it out of git's reach as you would
`~/.config`.

A deep state directory can push socket paths past the AF_UNIX limit (about 104 bytes on macOS, 108 on Linux):
`TYPEVAULT_RUN_DIR` (SDK: `runDir`) moves the daemon's sockets to a short directory of their own, one per vault.

One machine at a time may use a state directory. Its locks hold only within one machine (flock does not cross a bind
mount between macOS and a Linux VM), so a daemon also claims the directory in `run/daemon.holder` (its host, pid and
start time) for as long as it runs. A direct open or a daemon on another machine fails with `in_use` while that claim
is there, however old: a crashed daemon can't be told from a paused one, so its claim is never taken over from another
machine. If that machine's daemon is gone for good, delete the file; the same machine replaces its own leftover claim
on its next start. The host is the hostname, or `TYPEVAULT_HOST_ID` where the hostname changes on every start (a
container).

## Members and unlocking

```sh
typevault init                                   # the first time: choose a password, save the printed Secret Key
typevault unlock --for 8h                        # your key goes to the daemon until then
typevault lock                                   # ends the session and every live grant now
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

One unlock serves every git worktree of the repository. An agent working in another worktree reads through a session
the unlocked one starts there, with the worktree's own files and state, until the original session ends; `typevault
lock` in any of them locks them all. Only worktrees the repository lists count: a clone of the repository or a copy of
the vault needs its own `unlock`.

While a person's vault is locked, an agent's command fails with `the vault is locked: ask a human to run typevault
unlock`; in a terminal, the command asks for the password and unlocks on the spot. Owner commands (`tier`, `member`,
`key rotate`, ...) ask for the password every time, because only they open the owner key. Scripts pass passwords on
stdin with `--vault-password-stdin`, one per line. Removing an owner member isn't supported yet: every entry is also
sealed to the owner key, which can't be rotated yet.

## Git history

Old ciphertext stays in history forever. If a key leaks, rotate the key **and** every secret it could reach.
`typevault key rotate <tier>` rotates that tier and every tier it reaches, including transitively included tiers.
Rotate the listed secrets at their source, then re-set them; old ciphertext and previously exposed values remain compromised.
Removing an entry does not remove it from history. Adding a member rotates every tier they reach first, so their key
opens none of the ciphertext from before they joined; removing one rotates again and lists what they could read.

Every old revision is still validly signed, so each machine remembers the newest revision it has seen of every entry
and manifest, and every entry it deleted, and refuses older or deleted ones restored from history. A fresh clone trusts
what it first sees.

---

Back to the [README](../README.md).
