import { chmodSync, existsSync, readdirSync, realpathSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { appendAudit } from '../audit/log'
import { adoptCertWrites } from '../core/adopt'
import { randomHex, type SecretKey } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { atomicWrite, ensureDir } from '../core/fsx'
import { claimDaemon, type DaemonClaim, refuseForeignDaemon } from '../core/holder'
import { type Layout, localLayout } from '../core/layout'
import { holdLock, isLockHeld } from '../core/lock'
import { loadState, readOwner } from '../core/state'
import { Vault } from '../core/vault'
import { worktreeVaults } from '../core/worktrees'
import { adminRoutes, type Ceiling } from './admin-routes'
import { agentRoutes, type DaemonContext } from './agent-routes'
import { isDaemonAlive } from './client'
import { GrantStore, SESSION_CEILING } from './grants'
import { errorResponse, json, router } from './http'
import { type PromptOptions, PromptRequests } from './requests'
import { LOCKED_MESSAGE, startSession, stopDaemon } from './spawn'

const ADOPT_EVERY_MS = 60_000
const SOURCE_CHECK_MS = 1_000
const SESSION_LOCK = /^session-[0-9a-f]+\.lock$/

export type DaemonOptions = {
  readonly layout: Layout
  readonly env: Readonly<Record<string, string | undefined>>
  /** Member keys (or, in tests, the owner key). The daemon is the only process that holds them unlocked. */
  readonly keys: readonly SecretKey[]
  readonly prompt?: PromptOptions
  /**
   * An unlocked human session: a grant over everything the keys reach is written to `run/session.token` for
   * this user's CLI, and both end with the daemon. `sourceLock` makes it a session shared from another worktree's:
   * it serves only while that session's daemon holds this lock, which the OS drops however that daemon ends.
   */
  readonly session?: { readonly ttlMs: number; readonly sourceLock?: string }
}
export type RunningDaemon = {
  readonly stop: () => Promise<void>
  readonly ceilings: readonly Ceiling[]
  /** Settles when the host asks this daemon to stop over its control socket (how `stopDaemon` does it on Windows). */
  readonly stopRequested: Promise<void>
}

/** One admin socket per owner-signed ceiling, plus an uncapped `default` socket when this daemon holds the owner key. */
function ceilingsOf(vault: Vault): readonly Ceiling[] {
  const signed = Object.entries(vault.state.ceilings).map(([name, tier]) => ({ name, tier }))
  const owner = vault.keyring.owner !== undefined && vault.state.ceilings['default'] === undefined
  return owner ? [...signed, { name: 'default', tier: '*' }] : signed
}

async function openSession(context: DaemonContext, ttlMs: number): Promise<string> {
  const { vault, grants } = context
  const tiers = [...(await vault.keyring.reachableTiers())].sort()
  const { token, record } = grants.issue({ tiers, only: [], ttlMs, label: 'session', ceiling: SESSION_CEILING })
  atomicWrite(vault.layout.sessionFile, token, 0o600)
  await appendAudit(vault.layout, { action: 'grant.issue', mode: 'live', grant: record.id, label: 'session', tiers })
  return record.id
}

export async function startDaemon(options: DaemonOptions): Promise<RunningDaemon> {
  const { layout } = options
  ensureDir(layout.run, 0o700)
  ensureDir(layout.sockets, 0o700)
  refuseForeignDaemon(layout, options.env)
  if (await isDaemonAlive(layout.agentSocket))
    throw new TypeVaultError('conflict', 'a typevault daemon is already running')
  // Held until this daemon's cleanup is done: one still shutting down here keeps a replacement from starting, and
  // `stopDaemon` knows the old one is gone when the lock frees up, with no PID to trust.
  const release = holdLock(layout.daemonLock)
  if (release === undefined) throw new TypeVaultError('conflict', 'a typevault daemon is still shutting down here')
  let claim: DaemonClaim | undefined
  try {
    claim = claimDaemon(layout, options.env)
    return await serve(options, claim, release)
  } catch (error) {
    claim?.release()
    release()
    throw error
  }
}

async function serve(options: DaemonOptions, claim: DaemonClaim, releaseLock: () => void): Promise<RunningDaemon> {
  const { layout } = options
  for (const file of readdirSync(layout.sockets).filter((name) => name.endsWith('.sock'))) {
    rmSync(join(layout.sockets, file))
  }
  // Left by a session that ended without cleanup: removing them stops any worktree session still bound to one.
  for (const file of readdirSync(layout.run).filter((name) => SESSION_LOCK.test(name))) {
    rmSync(join(layout.run, file), { force: true })
  }
  if (options.keys.length === 0) throw new TypeVaultError('locked', 'the vault is locked (run `typevault unlock`)')
  const vault = await Vault.open(layout, options.keys, options.env)
  if (vault.keyring.owner === undefined && vault.member === undefined) {
    throw new TypeVaultError('denied', 'this key is not a member of the vault')
  }
  const ceilings = ceilingsOf(vault)
  if (ceilings.length === 0 && options.session === undefined)
    throw new TypeVaultError('invalid', 'no ceilings configured (typevault ceiling set <name> <tier>)')

  const { promise: stopRequested, resolve: requestStop } = Promise.withResolvers<void>()
  const member = vault.member === undefined ? undefined : vault.state.members[vault.member]
  const sourceLock = options.session?.sourceLock
  const sourceAlive = (): boolean => sourceLock === undefined || isLockHeld(sourceLock)
  // Held while this session runs, under a name no later session reuses: what worktree sessions shared from it check.
  const sessionLock = options.session === undefined ? undefined : join(layout.run, `session-${randomHex(8)}.lock`)
  const releaseSessionLock = sessionLock === undefined ? undefined : holdLock(sessionLock)
  const worktrees = new Map<string, Layout>()
  const attaching = new Set<Promise<void>>()
  let stopping = false
  const [key] = options.keys
  const attach =
    key === undefined || sessionLock === undefined
      ? undefined
      : async (target: string, exp: number): Promise<void> => {
          if (stopping) throw new TypeVaultError('locked', LOCKED_MESSAGE)
          const started = (async () => {
            const worktree = await worktreeLayout(vault, options.env, target)
            // Recorded before it starts, so a stop that comes in meanwhile still stops it.
            worktrees.set(target, worktree)
            await startWorktreeSession(worktree, options.env, key, exp, sessionLock)
          })()
          attaching.add(started)
          try {
            await started
          } finally {
            attaching.delete(started)
          }
        }
  const grants = new GrantStore(layout.grantsFile)
  // A session ends with its daemon, however that daemon ended: one killed before its cleanup left both of these.
  grants.revoke((record) => record.ceiling === SESSION_CEILING)
  rmSync(layout.sessionFile, { force: true })
  const context: DaemonContext = {
    vault,
    grants,
    sessions: new Map(),
    requests: new PromptRequests(vault, options.prompt ?? {}),
    ...(options.session === undefined
      ? {}
      : { sessionTiers: member?.tiers ?? [], ...(attach === undefined ? {} : { attach }) }),
  }
  // A shared session whose source is gone answers nothing but ping (how `stopDaemon` finds it) until it stops.
  const bound =
    (fetch: (request: Request) => Promise<Response>) =>
    async (request: Request): Promise<Response> =>
      sourceAlive() || new URL(request.url).pathname === '/v1/ping'
        ? fetch(request)
        : errorResponse(new TypeVaultError('locked', LOCKED_MESSAGE))
  const listen = (path: string, fetch: (request: Request) => Promise<Response>) => {
    const server = Bun.serve({ unix: path, fetch, maxRequestBodySize: 1 << 20 })
    // Windows sockets take the run directory's ACL; chmod there only toggles read-only.
    if (process.platform !== 'win32') chmodSync(path, 0o600)
    return server
  }
  const servers = [
    listen(layout.agentSocket, bound(router(agentRoutes(context)))),
    ...ceilings.map((ceiling) =>
      listen(layout.adminSocket(ceiling.name), bound(router(adminRoutes(context, ceiling)))),
    ),
    listen(
      layout.controlSocket,
      router({
        '/v1/shutdown': async () => {
          // Stopped once this response is out: stopping the server while its own request is in flight never settles.
          setTimeout(requestStop, 0)
          return json({ ok: true })
        },
      }),
    ),
  ]
  atomicWrite(join(layout.run, 'daemon.pid'), String(process.pid), 0o600)
  const session = options.session === undefined ? undefined : await openSession(context, options.session.ttlMs)
  const adopt = (): void => {
    adoptCertWrites(vault).then(undefined, (error: unknown) =>
      console.error('typevault daemon: adopting sealed writes failed', error),
    )
  }
  adopt()
  const adoption = setInterval(adopt, ADOPT_EVERY_MS)
  const watch = setInterval(() => {
    if (!sourceAlive()) requestStop()
  }, SOURCE_CHECK_MS)

  return {
    ceilings,
    stopRequested,
    stop: async () => {
      clearInterval(adoption)
      clearInterval(watch)
      stopping = true
      try {
        // An attachment still starting would otherwise leave its worktree unlocked after this stop.
        await Promise.allSettled(attaching)
        // The claim was cleared and someone else's daemon now owns the grants, session and run files. Saving this
        // daemon's stale grant store or removing those files would undo its successor's, so only local resources go.
        if (!claim.owns()) {
          await Promise.all(servers.map((server) => server.stop(true)))
          await context.requests.stop()
          return
        }
        // Worktrees share this session, so they lock with it.
        for (const worktree of worktrees.values()) await stopWorktree(worktree)
        if (session !== undefined) {
          context.grants.revoke((record) => record.id === session)
          if (existsSync(layout.sessionFile)) rmSync(layout.sessionFile)
        }

        await Promise.all(servers.map((server) => server.stop(true)))
        await context.requests.stop()
        for (const file of [
          layout.agentSocket,
          ...ceilings.map((c) => layout.adminSocket(c.name)),
          layout.controlSocket,
          join(layout.run, 'daemon.pid'),
        ]) {
          if (existsSync(file)) rmSync(file)
        }
      } finally {
        releaseSessionLock?.()
        if (sessionLock !== undefined) rmSync(sessionLock, { force: true })
        claim.release()
        releaseLock()
      }
    },
  }
}

/**
 * `target`, if it is the same vault in another worktree of this one's repository: where this session may start, so
 * agents working there aren't locked out. Anything else (a copy of the vault, a clone of the repository) gets no key:
 * only worktrees the repository lists count. The worktree keeps its own state and files, and trusts the owner this
 * session does, never one its own owner.json names on first use.
 */
async function worktreeLayout(vault: Vault, env: DaemonOptions['env'], target: string): Promise<Layout> {
  const listed = await worktreeVaults(vault.layout.vault)
  if (!existsSync(target) || !listed.includes(realpathSync(target))) {
    throw new TypeVaultError('denied', `${target} is not this vault in a worktree of its repository`)
  }
  const layout = localLayout(target, env)
  if (readOwner(layout).signPublic !== vault.state.owner.signPublic) {
    throw new TypeVaultError('tampered', "this worktree's vault has a different owner")
  }
  loadState(layout, { ...env, TYPEVAULT_OWNER: vault.state.owner.signPublic })
  return layout
}

async function startWorktreeSession(
  layout: Layout,
  env: DaemonOptions['env'],
  key: SecretKey,
  exp: number,
  sessionLock: string,
): Promise<void> {
  if (await isDaemonAlive(layout.agentSocket)) {
    if (existsSync(layout.sessionFile)) return
    await stopDaemon(layout)
  }
  await startSession(layout, env, key, exp - Date.now(), sessionLock)
}

async function stopWorktree(layout: Layout): Promise<void> {
  try {
    await stopDaemon(layout)
  } catch (error) {
    if (error instanceof TypeVaultError && error.code === 'not_found') return
    console.error(`typevault daemon: locking the worktree at ${layout.vault} failed`, error)
  }
}
