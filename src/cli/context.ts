import { existsSync, readFileSync } from 'node:fs'

import { z } from 'zod'

import { machineKeys } from '../access/keys'
import { ScopedVault } from '../access/scoped'
import { readSealedGrant } from '../access/sealed'
import { SealedAccess } from '../access/sealed-access'
import type { Access, EntryValue } from '../access/types'
import { Admin } from '../core/admin'
import type { SecretKey } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { atomicWrite } from '../core/fsx'
import { type Identity, readIdentity, sealedCopyPath, unlockIdentity } from '../core/identity'
import { findLocalVault, globalLayout, type Layout, localLayout } from '../core/layout'
import type { EntryName } from '../core/naming'
import { loadState } from '../core/state'
import { Vault } from '../core/vault'
import { worktreeVaults } from '../core/worktrees'
import { callDaemon, isDaemonAlive } from '../daemon/client'
import { LiveAccess } from '../daemon/live-access'
import { ensureDaemon, LOCKED_MESSAGE, startSession, stopDaemon } from '../daemon/spawn'
import { note } from './output'
import { type Passwords, passwords, passwordsFromStdin } from './password'

export type Env = Readonly<Record<string, string | undefined>>

const isSet = (value: string | undefined): boolean => value !== undefined && value !== ''

/** `-g` (`TYPEVAULT_GLOBAL`) or an explicit `TYPEVAULT_DIR` selects the global vault; otherwise the project's. */
export const wantsGlobal = (env: Env): boolean => {
  const global = env['TYPEVAULT_GLOBAL']?.toLowerCase()
  return (isSet(global) && global !== '0' && global !== 'false') || isSet(env['TYPEVAULT_DIR'])
}

/** The selected vault, or undefined when no project vault is found from `cwd`. Never falls back to the global one. */
export function findLayout(env: Env, cwd: string = process.cwd()): Layout | undefined {
  if (wantsGlobal(env)) return globalLayout(env)
  const dir = findLocalVault(cwd, env)
  return dir === undefined ? undefined : localLayout(dir, env)
}

export function layoutFrom(env: Env, cwd: string = process.cwd()): Layout {
  const layout = findLayout(env, cwd)
  if (layout === undefined) {
    throw new TypeVaultError(
      'not_found',
      'no vault here (run `typevault init` to create one, or pass -g for the global vault)',
    )
  }
  return layout
}

/**
 * The vault opened with this member's own key: direct mode, for owners and issuers. A machine member's key is at
 * hand; a human types their password, since only the daemon keeps an unlocked key around.
 */
export async function openDirect(env: Env): Promise<Vault> {
  const layout = layoutFrom(env)
  const machine = machineKeys(env)
  const identity = readIdentity(env)
  if (machine.length === 0 && identity === undefined) {
    throw new TypeVaultError('denied', 'no grant and no identity here (set TYPEVAULT_GRANT, or run typevault join)')
  }
  const keys = machine.length > 0 ? machine : [await unlockHuman(identity, passwords())]
  return Vault.open(layout, keys, env)
}

async function unlockHuman(identity: Identity | undefined, passwords: Passwords): Promise<SecretKey> {
  if (identity === undefined) throw new TypeVaultError('not_found', 'no identity here (run typevault init or join)')
  if (identity.kind === 'machine') return unlockIdentity(identity)
  return unlockIdentity(identity, await passwords.ask(`Password for ${identity.name}: `))
}

/**
 * Unlocks a human member's session: their key goes to a daemon that holds it for `ttlMs`, and this user's CLI
 * reads through the session grant it writes. Returns false when a session already runs.
 */
export async function unlockSession(env: Env, passwords: Passwords, ttlMs: number): Promise<boolean> {
  const layout = layoutFrom(env)
  if (await hasSession(layout)) return false
  const identity = readIdentity(env)
  const key = await unlockHuman(identity, passwords)
  const vault = await Vault.open(layout, [key], env)
  if (vault.member === undefined) {
    throw new TypeVaultError(
      'denied',
      `${identity?.name ?? 'you'} is not a member of this vault (share \`typevault identity show\` with an owner)`,
    )
  }
  if (identity?.kind === 'human') refreshSealedCopy(vault, identity)
  // A daemon without a session (a machine member's, or one left from before the vault was re-created) holds no key
  // of this person's, so it can't serve them: the session replaces it.
  if (await isDaemonAlive(layout.agentSocket)) {
    await stopDaemon(layout)
    note('replaced a running daemon that held no unlocked session')
  }
  await startSession(layout, env, key, ttlMs)
  return true
}

const hasSession = async (layout: Layout): Promise<boolean> =>
  existsSync(layout.sessionFile) && (await isDaemonAlive(layout.agentSocket))

/** This vault in the repository's other worktrees, where a session is unlocked: one unlock serves them all. */
export async function worktreeSessions(layout: Layout, env: Env): Promise<readonly Layout[]> {
  if (layout.scope !== 'local') return []
  const sessions: Layout[] = []
  for (const vault of await worktreeVaults(layout.vault)) {
    const worktree = localLayout(vault, env)
    if (await hasSession(worktree)) sessions.push(worktree)
  }
  return sessions
}

/** Starts here the session unlocked in another worktree, if any; that worktree's daemon checks this is one. */
async function shareWorktreeSession(layout: Layout, env: Env): Promise<boolean> {
  const [unlocked] = await worktreeSessions(layout, env)
  if (unlocked === undefined) return false
  const token = readFileSync(unlocked.sessionFile, 'utf8').trim()
  try {
    await callDaemon(unlocked.agentSocket, '/v1/attach', { vault: layout.vault }, z.object({ ok: z.literal(true) }), {
      token,
    })
  } catch (error) {
    if (error instanceof TypeVaultError) return false
    throw error
  }
  return true
}

/** After `passwd`, the copy committed in this vault still opens with the old password until it is replaced. */
function refreshSealedCopy(vault: Vault, identity: Identity & { readonly kind: 'human' }): void {
  const copy = sealedCopyPath(vault.layout, identity.name)
  if (existsSync(copy) && readFileSync(copy, 'utf8') !== identity.sealedKey) {
    atomicWrite(copy, identity.sealedKey)
    note(`updated ${copy} to your current password; commit it`)
  }
}

/** The vault's public, owner-signed state, readable without any key. */
export const openPublic = (env: Env): Promise<Vault> => Vault.open(layoutFrom(env), [], env)

export const openAdmin = async (env: Env): Promise<Admin> => new Admin(await openDirect(env))

export type ResolvedAccess =
  | { readonly kind: 'live'; readonly access: LiveAccess }
  | { readonly kind: 'sealed'; readonly access: SealedAccess }
  | { readonly kind: 'direct'; readonly access: ScopedVault }

/** `TYPEVAULT_GRANT` decides: `tvl1.` live via the daemon, `tvg1:`/`@path` sealed, unset = direct mode. */
export async function resolveAccess(env: Env): Promise<ResolvedAccess> {
  const grant = env['TYPEVAULT_GRANT']?.trim()
  if (grant === undefined || grant === '') {
    const machine = machineKeys(env)
    if (machine.length === 0) return { kind: 'live', access: await sessionAccess(env) }
    const tier = env['TYPEVAULT_TIER']
    const vault = await Vault.open(layoutFrom(env), machine, env)
    const ownTiers = vault.member === undefined ? [] : (vault.state.members[vault.member]?.tiers ?? [])
    const identity = { mode: 'direct' as const, ownTiers, ...(tier === undefined ? {} : { defaultTier: tier }) }
    return { kind: 'direct', access: new ScopedVault(vault, [], identity) }
  }
  if (grant.startsWith('tvl1.')) {
    const layout = layoutFrom(env)
    checkOwnerPin(layout, env)
    await ensureDaemon(layout, env)
    return { kind: 'live', access: new LiveAccess(layout.agentSocket, grant) }
  }
  if (grant.startsWith('tvg1:') || grant.startsWith('@')) {
    return { kind: 'sealed', access: new SealedAccess(await readSealedGrant(grant), findLayout(env), env) }
  }
  throw new TypeVaultError('invalid', 'TYPEVAULT_GRANT is not a typevault grant')
}

/**
 * A human member's CLI reads through the unlocked session's grant. On a terminal a locked vault asks for the
 * password right away; anywhere else (an agent) it stays locked until a human unlocks it.
 */
async function sessionAccess(env: Env): Promise<LiveAccess> {
  const layout = layoutFrom(env)
  checkOwnerPin(layout, env)
  if (!(await hasSession(layout)) && !(await shareWorktreeSession(layout, env))) {
    const identity = readIdentity(env)
    if (identity === undefined) {
      throw new TypeVaultError('denied', 'no grant and no identity here (set TYPEVAULT_GRANT, or run typevault join)')
    }
    const canAsk = process.stdin.isTTY || passwordsFromStdin()
    if (identity.kind !== 'human' || !canAsk) throw new TypeVaultError('locked', LOCKED_MESSAGE)
    await unlockSession(env, passwords(), DEFAULT_SESSION_MS)
  }
  // A session daemon from another release fails here instead of misreading this CLI's requests.
  await ensureDaemon(layout, env)
  return new LiveAccess(layout.agentSocket, readFileSync(layout.sessionFile, 'utf8').trim())
}

/**
 * A live connection reads through a daemon that may have trusted the owner without this process's pin, so a set
 * `TYPEVAULT_OWNER` is checked against the vault here, before anything is read through it.
 */
function checkOwnerPin(layout: Layout, env: Env): void {
  if (isSet(env['TYPEVAULT_OWNER'])) loadState(layout, env)
}

/**
 * Which of `names` the global vault holds, when the project vault was asked. It asks only an already unlocked global
 * session: never a password, a daemon start or a trust pin, and listing is not audited. Anything else answers none,
 * so a miss points at `-g` only when the global vault really has the name.
 */
export async function inGlobalVault(env: Env, names: readonly string[]): Promise<readonly string[]> {
  if (names.length === 0 || wantsGlobal(env) || isSet(env['TYPEVAULT_GRANT'])) return []
  const layout = globalLayout(env)
  if (!(await hasSession(layout))) return []
  try {
    const access = new LiveAccess(layout.agentSocket, readFileSync(layout.sessionFile, 'utf8').trim())
    const held = new Set<string>((await access.list()).map((entry) => entry.name))
    return names.filter((name) => held.has(name))
  } catch (error) {
    // Only a hint: a session that ends meanwhile, or a daemon from another release, gives none.
    if (error instanceof TypeVaultError || (error instanceof Error && 'code' in error && error.code === 'ENOENT')) {
      return []
    }
    throw error
  }
}

/** `access.get`, whose miss says so when the global vault has the name. */
export async function getEntry(access: Access, name: EntryName, reason?: string): Promise<EntryValue> {
  try {
    return await access.get(name, reason)
  } catch (error) {
    if (
      error instanceof TypeVaultError &&
      error.code === 'not_found' &&
      (await inGlobalVault(process.env, [name])).length > 0
    ) {
      throw new TypeVaultError(
        'not_found',
        `${error.message} in the project vault; the global vault has it: rerun with -g`,
        { cause: error },
      )
    }
    throw error
  }
}

/** How long an unlocked session lasts unless `unlock --for` says otherwise. */
export const DEFAULT_SESSION_MS = 8 * 60 * 60_000

export const accessOf = async (env: Env): Promise<Access> => (await resolveAccess(env)).access

/** A call on this process's admin socket (`TYPEVAULT_CEILING`, default `default`), starting the daemon if needed. */
export async function adminCall<T>(env: Env, path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
  const layout = layoutFrom(env)
  await ensureDaemon(layout, env)
  return callDaemon(layout.adminSocket(env['TYPEVAULT_CEILING'] ?? 'default'), path, body, schema)
}
