import { parseTtl } from '../access/scope'
import { ScopedVault } from '../access/scoped'
import { appendAudit } from '../audit/log'
import { TypeVaultError } from '../core/errors'
import type { Vault } from '../core/vault'
import { type GrantStore, type ResolvedGrant, SESSION_CEILING } from './grants'
import { type Handler, json, parseBody } from './http'
import { AttachBody, DeriveBody, MoveBody, NameBody, RequestBody, SetBody, ValuesBody, WaitBody } from './protocol'
import type { PromptRequests } from './requests'

export type DaemonContext = {
  readonly vault: Vault
  readonly grants: GrantStore
  /** One ScopedVault per live grant, so redaction knows every value that grant has read. */
  readonly sessions: Map<string, ScopedVault>
  readonly requests: PromptRequests
  /** The tiers an unlocked session's member holds directly: what `run` loads in bulk, as in direct mode. */
  readonly sessionTiers?: readonly string[]
  /** An unlocked session's: starts the same session in another worktree of this vault's repository, until `exp`. */
  readonly attach?: (vault: string, exp: number) => Promise<void>
}

function bearer(request: Request): string {
  const header = request.headers.get('authorization') ?? ''
  if (!header.startsWith('Bearer ')) throw new TypeVaultError('denied', 'missing grant (set TYPEVAULT_GRANT)')
  return header.slice('Bearer '.length)
}

function session(context: DaemonContext, request: Request): { grant: ResolvedGrant; access: ScopedVault } {
  const grant = context.grants.resolve(bearer(request))
  const { record } = grant
  const existing = context.sessions.get(record.id)
  if (existing !== undefined) return { grant, access: existing }
  // A session reaches every tier its member does, but like direct mode it never picks a tier for `set` on its own.
  const isSession = record.ceiling === SESSION_CEILING
  const access = new ScopedVault(context.vault, grant.chain, {
    mode: 'live',
    grant: record.id,
    label: record.label,
    owner: isSession && record.parent === undefined && context.vault.keyring.owner !== undefined,
    ownTiers: isSession ? (context.sessionTiers ?? []) : record.tiers,
    ...(isSession || record.tiers[0] === undefined ? {} : { defaultTier: record.tiers[0] }),
  })
  context.sessions.set(record.id, access)
  return { grant, access }
}

/** Routes on the agent socket. Every call needs a live grant; none can create a grant from nothing. */
export function agentRoutes(context: DaemonContext): Readonly<Record<string, Handler>> {
  return {
    // The PID lets `stopDaemon` signal exactly the process that answers here, never one a stale PID file names.
    '/v1/ping': async () => json({ ok: true, pid: process.pid }),
    '/v1/whoami': async (request) => {
      const { grant, access } = session(context, request)
      const { hash: _hash, ...record } = grant.record
      // `tiers` is what the grant may reach; `ownTiers` is what `run` loads in bulk, narrower for a session.
      return json({ ...record, ownTiers: await access.ownTiers() })
    },
    '/v1/list': async (request) => json(await session(context, request).access.list()),
    '/v1/get': async (request) => {
      const { name, reason } = await parseBody(request, NameBody)
      return json(await session(context, request).access.get(name, reason))
    },
    '/v1/values': async (request) => {
      const { only, reason } = await parseBody(request, ValuesBody)
      return json(await session(context, request).access.values(only, reason))
    },
    '/v1/set': async (request) => json(await session(context, request).access.set(await parseBody(request, SetBody))),
    '/v1/remove': async (request) => {
      const { name, tier } = await parseBody(request, NameBody)
      await session(context, request).access.remove(name, tier)
      return json({ ok: true })
    },
    '/v1/move': async (request) => {
      const { from, to } = await parseBody(request, MoveBody)
      await session(context, request).access.move(from, to)
      return json({ ok: true })
    },
    '/v1/read-values': async (request) => json(await session(context, request).access.readValues()),
    '/v1/derive': async (request) => {
      const { grant } = session(context, request)
      const body = await parseBody(request, DeriveBody)
      const remaining = Date.parse(grant.record.exp) - Date.now()
      const issued = context.grants.issue({
        tiers: body.tiers ?? grant.record.tiers,
        only: body.only,
        ttlMs: body.ttl === undefined ? remaining : parseTtl(body.ttl),
        // Prefixed with the parent's label so a derived grant can't pose as another session.
        label: `${grant.record.label}/${body.label ?? 'derived'}`,
        parent: grant.record.id,
        ceiling: grant.record.ceiling,
      })
      const { record } = issued
      await appendAudit(context.vault.layout, {
        action: 'grant.derive',
        mode: 'live',
        grant: record.id,
        label: record.label,
        tiers: record.tiers,
      })
      return json({ token: issued.token, id: record.id, exp: record.exp })
    },
    '/v1/request': async (request) => {
      const { grant, access } = session(context, request)
      const isLive = () => context.grants.isLive(grant.record.id)
      return json(
        await context.requests.open(
          { chain: grant.chain, grant: grant.record, access, isLive },
          await parseBody(request, RequestBody),
        ),
      )
    },
    // Only the session's own grant shares it: a grant derived from it (an agent's) can't widen itself to a worktree.
    '/v1/attach': async (request) => {
      const { record } = session(context, request).grant
      if (context.attach === undefined || record.ceiling !== SESSION_CEILING || record.parent !== undefined) {
        throw new TypeVaultError('denied', 'only an unlocked session can be shared with a worktree')
      }
      const { vault } = await parseBody(request, AttachBody)
      await context.attach(vault, Date.parse(record.exp))
      return json({ ok: true })
    },
    '/v1/request/wait': async (request) => {
      const { grant } = session(context, request)
      const { id } = await parseBody(request, WaitBody)
      return json({ stored: await context.requests.wait(grant.record.id, id) })
    },
  }
}
