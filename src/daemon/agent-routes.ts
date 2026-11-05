import { randomBytes } from 'node:crypto'

import { parseTtl } from '../access/scope'
import { ScopedVault } from '../access/scoped'
import { appendAudit } from '../audit/log'
import { TypeVaultError } from '../core/errors'
import type { Vault } from '../core/vault'
import { type GrantStore, type ResolvedGrant, SESSION_CEILING } from './grants'
import { type Handler, json, parseBody } from './http'
import {
  AttachBody,
  DeriveBody,
  ImportBody,
  ImportEntries,
  ImportStageBody,
  MoveBody,
  NameBody,
  RequestBody,
  SetBody,
  ValuesBody,
  WaitBody,
} from './protocol'
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

type StagedImport = {
  readonly grant: string
  readonly parts: Uint8Array[]
  bytes: number
  exp: number
}

/** What staged imports may hold in memory at once, across every grant. */
const MAX_STAGED_BYTES = 64 << 20
const STAGED_TTL_MS = 10 * 60_000

/** Routes on the agent socket. Every call needs a live grant; none can create a grant from nothing. */
export function agentRoutes(context: DaemonContext): Readonly<Record<string, Handler>> {
  // An import, or even one entry, can exceed a request body, so its serialized JSON arrives in chunks and is written
  // by one final call, all or nothing.
  const staged = new Map<string, StagedImport>()
  const stagedBy = (upload: string, grant: string): StagedImport => {
    const found = staged.get(upload)
    if (found === undefined || found.grant !== grant || found.exp <= Date.now()) {
      throw new TypeVaultError('not_found', 'no such import upload (it may have expired)')
    }
    return found
  }
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
    '/v1/unreadable': async (request) => json({ count: await session(context, request).access.unreadableEntries() }),
    '/v1/get': async (request) => {
      const { name, reason } = await parseBody(request, NameBody)
      return json(await session(context, request).access.get(name, reason))
    },
    '/v1/values': async (request) => {
      const { only, reason } = await parseBody(request, ValuesBody)
      return json(await session(context, request).access.values(only, reason))
    },
    '/v1/set': async (request) => json(await session(context, request).access.set(await parseBody(request, SetBody))),
    '/v1/import/stage': async (request) => {
      const { grant } = session(context, request)
      const body = await parseBody(request, ImportStageBody)
      const now = Date.now()
      for (const [id, upload] of staged) if (upload.exp <= now) staged.delete(id)
      const part = Buffer.from(body.chunk, 'base64')
      const bytes = part.byteLength
      const held = [...staged.values()].reduce((sum, upload) => sum + upload.bytes, 0)
      if (held + bytes > MAX_STAGED_BYTES) throw new TypeVaultError('invalid', 'this import is too large (over 64 MiB)')
      const id = body.upload ?? randomBytes(16).toString('base64url')
      const upload =
        body.upload === undefined
          ? { grant: grant.record.id, parts: [], bytes: 0, exp: 0 }
          : stagedBy(id, grant.record.id)
      upload.parts.push(part)
      upload.bytes += bytes
      upload.exp = now + STAGED_TTL_MS
      staged.set(id, upload)
      return json({ upload: id })
    },
    '/v1/import': async (request) => {
      const { grant, access } = session(context, request)
      const { upload, tier } = await parseBody(request, ImportBody)
      const { parts } = stagedBy(upload, grant.record.id)
      staged.delete(upload)
      let value: unknown
      try {
        value = JSON.parse(Buffer.concat(parts).toString('utf8'))
      } catch (error) {
        if (error instanceof SyntaxError) throw new TypeVaultError('invalid', 'the staged import is not JSON')
        throw error
      }
      const entries = ImportEntries.safeParse(value)
      if (!entries.success) {
        throw new TypeVaultError('invalid', `bad import: ${entries.error.issues[0]?.message ?? 'invalid'}`)
      }
      return json(await access.importEntries(entries.data, tier))
    },
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
