import { existsSync } from 'node:fs'
import { homedir, hostname } from 'node:os'
import { dirname, join, resolve } from 'node:path'

import { sha256Hex } from './crypto'
import { utf8 } from './encoding'

export type Layout = {
  /** `global`: one vault per user. `local`: a `.typevault/` committed in a project. */
  readonly scope: 'global' | 'local'
  /** Private state (trust pin, audit, run). Never committed. */
  readonly root: string
  /** The committable part: ciphertext and signed manifests only. */
  readonly vault: string
  readonly entries: string
  readonly tiersDir: string
  readonly ownerFile: string
  readonly tiersFile: string
  readonly membersFile: string
  /** Each human member's password-sealed key, so a new device needs only the password and Secret Key. */
  readonly membersDir: string
  /** The owner key wrapped to each owner member. */
  readonly ownerWrapsDir: string
  readonly signersFile: string
  readonly ceilingsFile: string
  /** This checkout's audit anchors: one committed file per audit chain, so clones never check each other's. */
  readonly anchorsFile: string
  /** Anchors from before chains had their own file; still checked against this checkout's log. */
  readonly legacyAnchorsFile: string
  readonly txnDir: string
  readonly trustFile: string
  readonly audit: string
  readonly auditLog: string
  readonly run: string
  readonly lockFile: string
  readonly auditLock: string
  readonly grantsFile: string
  /** The unlocked session's grant token, readable only by this user while the daemon runs. */
  readonly sessionFile: string
  readonly revisionsFile: string
  readonly agentSocket: string
  readonly adminSocket: (ceiling: string) => string
}

type Env = Readonly<Record<string, string | undefined>>

/** The directory a project vault lives in, next to the project's files. */
export const LOCAL_VAULT_DIR = '.typevault'

/** `TYPEVAULT_DIR`, else `$XDG_CONFIG_HOME/typevault`, else `~/.config/typevault`. */
export function resolveRoot(env: Env = process.env): string {
  const explicit = env['TYPEVAULT_DIR']
  if (explicit !== undefined && explicit !== '') return explicit
  const xdg = env['XDG_CONFIG_HOME']
  return join(xdg !== undefined && xdg !== '' ? xdg : join(homedir(), '.config'), 'typevault')
}

/** The global vault, or any vault kept whole under `root` (`vault/` beside `keys/`). */
export const layoutOf = (root: string): Layout => build('global', root, join(root, 'vault'))

/**
 * A project vault at `dir`. Trust, audit and run state belong to this checkout (keyed by its path), so a replaced
 * owner.json still meets the old pin and two clones never share a daemon or a transaction journal.
 */
export function localLayout(dir: string, env: Env = process.env): Layout {
  return build('local', join(resolveRoot(env), 'checkouts', shortHash(resolve(dir))), dir)
}

const shortHash = (value: string): string => sha256Hex(utf8(value)).slice(0, 16)

/** A vault's id, derived from its owner key. */
export const vaultIdOf = (ownerSignPublic: string): string => shortHash(ownerSignPublic)

/** The nearest `.typevault/` holding an initialized vault, from `from` up to the filesystem root. */
export function findLocalVault(from: string): string | undefined {
  for (let dir = from; ; dir = dirname(dir)) {
    const candidate = join(dir, LOCAL_VAULT_DIR)
    if (existsSync(join(candidate, 'owner.json'))) return candidate
    if (dirname(dir) === dir) return undefined
  }
}

function build(scope: Layout['scope'], root: string, vault: string): Layout {
  const audit = join(root, 'audit')
  const run = join(root, 'run')
  return {
    scope,
    root,
    vault,
    entries: join(vault, 'entries'),
    tiersDir: join(vault, 'tiers'),
    ownerFile: join(vault, 'owner.json'),
    tiersFile: join(vault, 'tiers.json'),
    membersFile: join(vault, 'members.json'),
    membersDir: join(vault, 'members'),
    ownerWrapsDir: join(vault, 'owner'),
    signersFile: join(vault, 'signers.json'),
    ceilingsFile: join(vault, 'ceilings.json'),
    // Named by where the log lives, never by the log itself: a log rewritten from its first record keeps its anchors.
    anchorsFile: join(vault, 'audit-anchors', `${shortHash(`${hostname()}\0${root}`)}.jsonl`),
    legacyAnchorsFile: join(vault, 'audit-anchors.jsonl'),
    // Staging lives in run/, which is never committed: a txn dir from git must not be able to steer deletes.
    txnDir: join(run, 'txn'),
    trustFile: join(root, 'trust.json'),
    audit,
    auditLog: join(audit, 'log.jsonl'),
    run,
    lockFile: join(run, 'lock'),
    auditLock: join(run, 'audit.lock'),
    grantsFile: join(run, 'grants.json'),
    sessionFile: join(run, 'session.token'),
    revisionsFile: join(run, 'revisions.json'),
    agentSocket: join(run, 'agent.sock'),
    adminSocket: (ceiling: string) => join(run, `admin-${ceiling}.sock`),
  }
}
