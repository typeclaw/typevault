import { parseTtl } from '../access/scope'
import { issueSealedGrant } from '../access/sealed'
import { appendAudit, readAudit } from '../audit/log'
import { TypeVaultError } from '../core/errors'
import { reach } from '../core/state'
import type { DaemonContext } from './agent-routes'
import { type Handler, json, parseBody } from './http'
import { AuditBody, GrantBody, RevokeBody } from './protocol'

/** `*` means the owner's own socket: no ceiling. */
export type Ceiling = { readonly name: string; readonly tier: string | '*' }

function checkCeiling(context: DaemonContext, ceiling: Ceiling, tiers: readonly string[]): void {
  const state = context.vault.state
  for (const tier of tiers) {
    if (state.tiers[tier] === undefined) throw new TypeVaultError('not_found', `no tier "${tier}"`)
    if (ceiling.tier !== '*' && !reach(state.tiers, ceiling.tier).has(tier)) {
      throw new TypeVaultError('denied', `tier "${tier}" is above this socket's ceiling ("${ceiling.tier}")`)
    }
  }
}

/** Routes on an admin socket: issuing and revoking grants, bounded by that socket's ceiling. */
/** An uncapped socket sees every grant; a capped one only the grants it issued. */
const ownedBy = (ceiling: Ceiling) => (record: { readonly ceiling: string }) =>
  ceiling.tier === '*' || record.ceiling === ceiling.name

export function adminRoutes(context: DaemonContext, ceiling: Ceiling): Readonly<Record<string, Handler>> {
  return {
    '/v1/ping': async () => json({ ok: true }),
    '/v1/status': async () =>
      json({
        ceiling: ceiling.tier,
        tiers: Object.keys(context.vault.state.tiers),
        grants: context.grants.list().length,
      }),
    '/v1/grant': async (request) => {
      const body = await parseBody(request, GrantBody)
      checkCeiling(context, ceiling, body.tiers)
      const ttlMs = parseTtl(body.ttl)
      if (body.sealed) {
        const token = await issueSealedGrant(context.vault, {
          tiers: body.tiers,
          only: body.only,
          ttlMs,
          label: body.label,
        })
        return json({ token })
      }
      const { token, record } = context.grants.issue({
        tiers: body.tiers,
        only: body.only,
        ttlMs,
        label: body.label,
        ceiling: ceiling.name,
      })
      await appendAudit(context.vault.layout, {
        action: 'grant.issue',
        mode: 'live',
        grant: record.id,
        label: record.label,
        tiers: record.tiers,
      })
      return json({ token, id: record.id, exp: record.exp })
    },
    '/v1/grants': async () => json(context.grants.list().filter(ownedBy(ceiling))),
    '/v1/revoke': async (request) => {
      const { id, label } = await parseBody(request, RevokeBody)
      if (id === undefined && label === undefined) throw new TypeVaultError('invalid', 'revoke needs an id or a label')
      const owned = ownedBy(ceiling)
      const revoked = context.grants.revoke(
        (record) => owned(record) && (record.id === id || (label !== undefined && record.label === label)),
      )
      for (const grant of revoked) context.sessions.delete(grant)
      await appendAudit(context.vault.layout, {
        action: 'grant.revoke',
        mode: 'live',
        entries: [],
        tiers: [],
        ...(label === undefined ? {} : { label }),
        ...(id === undefined ? {} : { grant: id }),
      })
      return json({ revoked })
    },
    '/v1/audit': async (request) => {
      // The trail names entries of every tier, so only the uncapped socket may read it.
      if (ceiling.tier !== '*')
        throw new TypeVaultError('denied', 'the audit trail is only readable on the owner socket')
      const { label } = await parseBody(request, AuditBody)
      return json(readAudit(context.vault.layout).filter((record) => label === undefined || record['label'] === label))
    },
  }
}
