import { existsSync, realpathSync } from 'node:fs'
import { homedir, hostname } from 'node:os'
import { dirname, join, resolve } from 'node:path'

import { sha256Hex } from './crypto'
import { utf8 } from './encoding'

export type Layout = {
  /** `global`: one vault per user, `~/.typevault/`. `local`: a `.typevault/` committed in a project. */
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
  /** Held by the daemon from start until its cleanup is done: whether a daemon is still here, without PIDs. */
  readonly daemonLock: string
  /** The unlocked session's grant token, readable only by this user while the daemon runs. */
  readonly sessionFile: string
  readonly revisionsFile: string
  readonly agentSocket: string
  readonly adminSocket: (ceiling: string) => string
  /** Host-only: how `stopDaemon` stops the daemon where there is no SIGTERM (Windows). Never mounted into a sandbox. */
  readonly controlSocket: string
}

type Env = Readonly<Record<string, string | undefined>>

/** The directory a project vault lives in, next to the project's files. */
export const LOCAL_VAULT_DIR = '.typevault'

/**
 * `$XDG_CONFIG_HOME/typevault`, else `~/.config/typevault`: this device's identity and every vault's private state,
 * never any vault itself.
 */
export function configDir(env: Env = process.env): string {
  const xdg = env['XDG_CONFIG_HOME']
  return join(xdg !== undefined && xdg !== '' ? xdg : join(home(env), '.config'), 'typevault')
}

/** `TYPEVAULT_DIR`, else `~/.typevault`. */
export function globalVaultDir(env: Env = process.env): string {
  const explicit = env['TYPEVAULT_DIR']
  return explicit !== undefined && explicit !== '' ? explicit : join(home(env), LOCAL_VAULT_DIR)
}

function home(env: Env): string {
  const explicit = env['HOME']
  return explicit !== undefined && explicit !== '' ? explicit : homedir()
}

/** The global vault: laid out like a project vault, its private state kept the same way. */
export const globalLayout = (env: Env = process.env): Layout => vaultLayout('global', globalVaultDir(env), env)

/** A project vault at `dir`. */
export const localLayout = (dir: string, env: Env = process.env): Layout => vaultLayout('local', dir, env)

/**
 * Trust, audit and run state belong to this checkout (keyed by its path), so a replaced owner.json still meets the
 * old pin and two clones never share a daemon or a transaction journal.
 */
const vaultLayout = (scope: Layout['scope'], dir: string, env: Env): Layout =>
  build(scope, join(configDir(env), 'checkouts', shortHash(resolve(dir))), dir)

// A home directory reached through a symlink (macOS's /tmp, say) is still the same directory.
const canonical = (path: string): string => (existsSync(path) ? realpathSync(path) : resolve(path))

const shortHash = (value: string): string => sha256Hex(utf8(value)).slice(0, 16)

/** A vault's id, derived from its owner key. */
export const vaultIdOf = (ownerSignPublic: string): string => shortHash(ownerSignPublic)

/**
 * The nearest `.typevault/` holding an initialized vault, from `from` up to the filesystem root. The global vault is
 * one too, in the home directory, but it is never taken for a project's.
 */
export function findLocalVault(from: string, env: Env = process.env): string | undefined {
  const global = canonical(globalVaultDir(env))
  for (let dir = from; ; dir = dirname(dir)) {
    const candidate = join(dir, LOCAL_VAULT_DIR)
    if (existsSync(join(candidate, 'owner.json')) && canonical(candidate) !== global) return candidate
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
    daemonLock: join(run, 'daemon.lock'),
    sessionFile: join(run, 'session.token'),
    revisionsFile: join(run, 'revisions.json'),
    agentSocket: join(run, 'agent.sock'),
    adminSocket: (ceiling: string) => join(run, `admin-${ceiling}.sock`),
    controlSocket: join(run, 'control.sock'),
  }
}
