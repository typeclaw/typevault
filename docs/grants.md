# Grants

Live and sealed grants, ceilings, asking a human for a secret, and SDK options.

## Grants

|                  | Live (default)                | Sealed (`--sealed`)            |
| ---------------- | ----------------------------- | ------------------------------ |
| Needs the daemon | yes                           | no                             |
| Audit            | every read                    | issue time (reads best-effort) |
| TTL / revocation | enforced / instant            | advisory / impossible          |
| Use for          | laptops, containers, typeclaw | CI, one-shot containers        |

A sealed grant can write, within its tiers and `--only`, until its certificate expires by the **reader's** clock. It replaces only the entries it was issued with and the ones it wrote itself; writing a name added after it was issued adds a second copy for `doctor` to settle.
A daemon (every minute) or `typevault doctor --fix` adopts those writes by re-signing them. Writes nobody adopts
before expiry stop being trusted, and `doctor --fix` lists them. The holder keeps the signing key and picks each write's
timestamp, so nothing proves such a write came before the expiry: the owner keeps one only by naming it, with
`typevault doctor --fix --adopt-expired <name,...>`.

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

## SDK options

`createClient` takes `grant` (default `TYPEVAULT_GRANT`), `dir` and `env`; `dir` (default `TYPEVAULT_DIR`) selects a
global-style vault, and without it the vault is chosen like the CLI's. Without a grant it
refuses unless you pass `direct: true`, which reads through the unlocked session, or loads a machine member's key
into your process; keep that to issuers.
`createAdmin` takes `dir`, `ceiling` and `env`, and offers `grant`, `list` and `revoke`. Both take `global: true` to use
the global vault, like `-g`.

---

Back to the [README](../README.md).
