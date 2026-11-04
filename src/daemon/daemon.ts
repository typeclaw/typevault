import { chmodSync, existsSync, readdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { anchorAudit, appendAudit } from '../audit/log'
import { adoptCertWrites } from '../core/adopt'
import type { SecretKey } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { atomicWrite, ensureDir } from '../core/fsx'
import { claimDaemon, type DaemonClaim, refuseForeignDaemon } from '../core/holder'
import type { Layout } from '../core/layout'
import { holdLock } from '../core/lock'
import { Vault } from '../core/vault'
import { adminRoutes, type Ceiling } from './admin-routes'
import { agentRoutes, type DaemonContext } from './agent-routes'
import { isDaemonAlive } from './client'
import { GrantStore, SESSION_CEILING } from './grants'
import { json, router } from './http'
import { type PromptOptions, PromptRequests } from './requests'

const ADOPT_EVERY_MS = 60_000

export type DaemonOptions = {
  readonly layout: Layout
  readonly env: Readonly<Record<string, string | undefined>>
  /** Member keys (or, in tests, the owner key). The daemon is the only process that holds them unlocked. */
  readonly keys: readonly SecretKey[]
  readonly prompt?: PromptOptions
  /**
   * An unlocked human session: a grant over everything the keys reach is written to `run/session.token` for
   * this user's CLI, and both end with the daemon.
   */
  readonly session?: { readonly ttlMs: number }
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
  const context: DaemonContext = {
    vault,
    grants: new GrantStore(layout.grantsFile),
    sessions: new Map(),
    requests: new PromptRequests(vault, options.prompt ?? {}),
    ...(options.session === undefined ? {} : { sessionTiers: member?.tiers ?? [] }),
  }
  const listen = (path: string, fetch: (request: Request) => Promise<Response>) => {
    const server = Bun.serve({ unix: path, fetch, maxRequestBodySize: 1 << 20 })
    // Windows sockets take the run directory's ACL; chmod there only toggles read-only.
    if (process.platform !== 'win32') chmodSync(path, 0o600)
    return server
  }
  const servers = [
    listen(layout.agentSocket, router(agentRoutes(context))),
    ...ceilings.map((ceiling) => listen(layout.adminSocket(ceiling.name), router(adminRoutes(context, ceiling)))),
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

  return {
    ceilings,
    stopRequested,
    stop: async () => {
      clearInterval(adoption)
      try {
        // The claim was cleared and someone else's daemon now owns the grants, session and run files. Saving this
        // daemon's stale grant store or removing those files would undo its successor's, so only local resources go.
        if (!claim.owns()) {
          await Promise.all(servers.map((server) => server.stop(true)))
          await context.requests.stop()
          return
        }
        if (session !== undefined) {
          context.grants.revoke((record) => record.id === session)
          if (existsSync(layout.sessionFile)) rmSync(layout.sessionFile)
        }
        await Promise.all(servers.map((server) => server.stop(true)))
        await context.requests.stop()
        // A vault deleted under its daemon has nowhere left to anchor (and writing there would half re-create it).
        if (existsSync(layout.ownerFile)) await anchorAudit(layout)
        for (const file of [
          layout.agentSocket,
          ...ceilings.map((c) => layout.adminSocket(c.name)),
          layout.controlSocket,
          join(layout.run, 'daemon.pid'),
        ]) {
          if (existsSync(file)) rmSync(file)
        }
      } finally {
        claim.release()
        releaseLock()
      }
    },
  }
}
