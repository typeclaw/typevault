import { parseTtl } from '../access/scope'
import { ScopedVault } from '../access/scoped'
import { appendAudit } from '../audit/log'
import { TypeVaultError } from '../core/errors'
import type { Vault } from '../core/vault'
import type { GrantStore, ResolvedGrant } from './grants'
import { type Handler, json, parseBody } from './http'
import { DeriveBody, MoveBody, NameBody, RequestBody, SetBody, ValuesBody, WaitBody } from './protocol'
import type { PromptRequests } from './requests'

export type DaemonContext = {
  readonly vault: Vault
  readonly grants: GrantStore
  /** One ScopedVault per live grant, so redaction knows every value that grant has read. */
  readonly sessions: Map<string, ScopedVault>
  readonly requests: PromptRequests
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
  const access = new ScopedVault(context.vault, grant.chain, {
    mode: 'live',
    grant: record.id,
    label: record.label,
    ownGroups: record.groups,
    ...(record.groups[0] === undefined ? {} : { defaultGroup: record.groups[0] }),
  })
  context.sessions.set(record.id, access)
  return { grant, access }
}

/** Routes on the agent socket. Every call needs a live grant; none can create a grant from nothing. */
export function agentRoutes(context: DaemonContext): Readonly<Record<string, Handler>> {
  return {
    '/v1/ping': async () => json({ ok: true }),
    '/v1/whoami': async (request) => {
      const { grant } = session(context, request)
      const { hash: _hash, ...record } = grant.record
      return json(record)
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
      const { name, group } = await parseBody(request, NameBody)
      await session(context, request).access.remove(name, group)
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
        groups: body.groups ?? grant.record.groups,
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
        groups: record.groups,
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
    '/v1/request/wait': async (request) => {
      const { grant } = session(context, request)
      const { id } = await parseBody(request, WaitBody)
      return json({ stored: await context.requests.wait(grant.record.id, id) })
    },
  }
}
