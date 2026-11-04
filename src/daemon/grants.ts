import { timingSafeEqual } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'

import { z } from 'zod'

import type { ScopeChain } from '../access/scope'
import { randomHex, randomToken, sha256Hex } from '../core/crypto'
import { utf8 } from '../core/encoding'
import { TypeVaultError } from '../core/errors'
import { atomicWrite } from '../core/fsx'

const RecordSchema = z.object({
  id: z.string(),
  hash: z.string(),
  label: z.string(),
  tiers: z.array(z.string()),
  only: z.array(z.string()),
  exp: z.iso.datetime(),
  created: z.iso.datetime(),
  parent: z.string().optional(),
  /** The admin socket that issued it (derived grants inherit it). */
  ceiling: z.string(),
  revoked: z.boolean().optional(),
})
export type GrantRecord = z.infer<typeof RecordSchema>
export type GrantRequest = {
  readonly tiers: readonly string[]
  readonly only: readonly string[]
  readonly ttlMs: number
  readonly label: string
  readonly parent?: string
  readonly ceiling: string
}
export type ResolvedGrant = { readonly record: GrantRecord; readonly chain: ScopeChain }

const PREFIX = 'tvl1'

/** The ceiling name marking an unlocked session's grant (and grants derived from it). */
export const SESSION_CEILING = 'session'

/**
 * Live grants, persisted (hashed) so a daemon restart doesn't cut sessions off.
 * A token is `tvl1.<id>.<secret>`; only sha256(secret) is stored.
 */
export class GrantStore {
  readonly #path: string
  #records: GrantRecord[]

  constructor(path: string) {
    this.#path = path
    this.#records = existsSync(path) ? z.array(RecordSchema).parse(JSON.parse(readFileSync(path, 'utf8'))) : []
  }

  #save(): void {
    const now = Date.now()
    this.#records = this.#records.filter((record) => Date.parse(record.exp) > now)
    atomicWrite(this.#path, JSON.stringify(this.#records), 0o600)
  }

  issue(request: GrantRequest): { readonly token: string; readonly record: GrantRecord } {
    const parent = request.parent === undefined ? undefined : this.#records.find((r) => r.id === request.parent)
    const requestedExp = Date.now() + request.ttlMs
    const exp = parent === undefined ? requestedExp : Math.min(requestedExp, Date.parse(parent.exp))
    const secret = randomToken(32)
    const record: GrantRecord = {
      id: randomHex(8),
      hash: sha256Hex(utf8(secret)),
      label: request.label,
      tiers: [...request.tiers],
      only: [...request.only],
      exp: new Date(exp).toISOString(),
      created: new Date().toISOString(),
      ceiling: request.ceiling,
      ...(request.parent === undefined ? {} : { parent: request.parent }),
    }
    this.#records.push(record)
    this.#save()
    return { token: `${PREFIX}.${record.id}.${secret}`, record }
  }

  /** The grant behind a token plus its ancestors' scopes; any revoked or expired link refuses it. */
  resolve(token: string): ResolvedGrant {
    const [prefix, id, secret] = token.split('.')
    const record = this.#records.find((r) => r.id === id)
    if (
      prefix !== PREFIX ||
      secret === undefined ||
      record === undefined ||
      !timingSafeEqual(Buffer.from(record.hash, 'hex'), Buffer.from(sha256Hex(utf8(secret)), 'hex'))
    ) {
      throw new TypeVaultError('denied', 'unknown grant')
    }
    const chain: GrantRecord[] = []
    for (let link: GrantRecord | undefined = record; link !== undefined;) {
      if (link.revoked === true) throw new TypeVaultError('denied', 'this grant was revoked')
      if (Date.parse(link.exp) <= Date.now()) throw new TypeVaultError('expired', 'this grant has expired')
      chain.push(link)
      const parentId: string | undefined = link.parent
      link = parentId === undefined ? undefined : this.#records.find((r) => r.id === parentId)
      if (parentId !== undefined && link === undefined) throw new TypeVaultError('denied', 'parent grant is gone')
    }
    return { record, chain: chain.map(({ tiers, only }) => ({ tiers, only })) }
  }

  /** Whether grant `id` and all its ancestors are still unrevoked and unexpired. */
  isLive(id: string): boolean {
    for (let link = this.#records.find((r) => r.id === id); link !== undefined;) {
      if (link.revoked === true || Date.parse(link.exp) <= Date.now()) return false
      const parentId: string | undefined = link.parent
      if (parentId === undefined) return true
      link = this.#records.find((r) => r.id === parentId)
    }
    return false
  }

  /** Revokes matching grants and everything derived from them. Returns the revoked ids. */
  revoke(match: (record: GrantRecord) => boolean): readonly string[] {
    const revoked = new Set(this.#records.filter(match).map((record) => record.id))
    let grew = true
    while (grew) {
      grew = false
      for (const record of this.#records) {
        if (record.parent !== undefined && revoked.has(record.parent) && !revoked.has(record.id)) {
          revoked.add(record.id)
          grew = true
        }
      }
    }
    this.#records = this.#records.map((record) => (revoked.has(record.id) ? { ...record, revoked: true } : record))
    this.#save()
    return [...revoked]
  }

  list(): readonly Omit<GrantRecord, 'hash'>[] {
    return this.#records.filter((record) => record.revoked !== true).map(({ hash: _hash, ...rest }) => rest)
  }
}
