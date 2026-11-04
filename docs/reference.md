# Reference

Environment variables, on-disk layout, and known limits.

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
    entries/        # one signed file per entry, named <tier>.<random id>
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

## Known limits

- Redaction is best effort: values shorter than 4 characters, hex or composed encodings (such as HTTP Basic auth) can slip
  through. Prefer `run` over `get`.
- The local audit chain is unkeyed: a process running as the same user can rewrite records since the last anchor.
- Same-user processes that can reach one admin socket share its ceiling; isolate sessions to enforce more.

---

Back to the [README](../README.md).
