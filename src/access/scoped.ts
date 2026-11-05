import { appendAudit, type AuditEvent, type AuditMode } from '../audit/log'
import { signerOf } from '../core/entries'
import { TypeVaultError } from '../core/errors'
import { withLock } from '../core/lock'
import { type EntryName, type Field, matchesOnly } from '../core/naming'
import { resolveName, type StoredEntry, type Vault } from '../core/vault'
import { needsRefresh, refreshOAuth } from '../oauth/refresh'
import { secretValues } from './env'
import { allowsEntry, allowsTier, type ScopeChain } from './scope'
import {
  type Access,
  type EntrySummary,
  type EntryValue,
  entryInputOf,
  type SetInput,
  toSummary,
  toValue,
  writtenFromAbove,
} from './types'

export type ScopedIdentity = {
  readonly mode: AuditMode
  readonly grant?: string
  readonly label?: string
  /** The owner's own session, never a grant delegated from it. */
  readonly owner?: boolean
  /** Tiers held directly; see `Access.ownTiers`. */
  readonly ownTiers?: readonly string[]
  /** Tier used by `set` when the caller names none. */
  readonly defaultTier?: string
}

const valueOf = (entry: StoredEntry): EntryValue =>
  toValue(entry.envelope.tier, entry.envelope.id, entry.envelope.rev, entry.payload)

/**
 * Vault access bounded by a scope chain, with every read and write audited. The daemon wraps each live
 * grant in one; direct mode uses an empty chain. Values it hands out are remembered for redaction.
 */
export class ScopedVault implements Access {
  readonly #vault: Vault
  readonly #chain: ScopeChain
  readonly #identity: ScopedIdentity
  readonly #handedOut = new Set<string>()

  constructor(vault: Vault, chain: ScopeChain, identity: ScopedIdentity) {
    this.#vault = vault
    this.#chain = chain
    this.#identity = identity
  }

  #audit(event: Omit<AuditEvent, 'mode' | 'grant' | 'label'>): Promise<void> {
    const { mode, grant, label } = this.#identity
    return appendAudit(this.#vault.layout, {
      ...event,
      mode,
      ...(grant === undefined ? {} : { grant }),
      ...(label === undefined ? {} : { label }),
    })
  }

  #allows(entry: StoredEntry): boolean {
    return allowsEntry(this.#chain, this.#vault.state, entry.envelope.tier, entry.payload.name)
  }

  /** One entry per name: the copy each name resolves to within this scope (see `resolveName`). */
  async #visible(): Promise<readonly StoredEntry[]> {
    const { entries } = await this.#vault.scan()
    const byName = Map.groupBy(
      entries.filter((entry) => this.#allows(entry)),
      (entry) => entry.payload.name,
    )
    return [...byName.values()].flatMap((copies) => resolveName(this.#vault.state.tiers, copies) ?? [])
  }

  async #find(name: EntryName): Promise<StoredEntry> {
    const entry = await this.#vault.find(name)
    if (entry === undefined || !this.#allows(entry)) throw new TypeVaultError('not_found', `no entry named ${name}`)
    return entry
  }

  async #signerFor(tier: string): Promise<ReturnType<typeof signerOf>> {
    // The owner signs its own writes in direct mode or its own session. Delegated grants use tier keys,
    // so a grant's writes never look owner-authored.
    const owner =
      this.#identity.mode === 'direct' || this.#identity.owner === true ? this.#vault.keyring.owner : undefined
    const key = owner ?? (await this.#vault.keyring.unlock(tier)) ?? this.#vault.keyring.owner
    if (key === undefined) throw new TypeVaultError('denied', `no key here can write tier "${tier}"`)
    return signerOf(key)
  }

  /** OAuth fields past their expiry are refreshed and written back before anyone reads them. */
  async #fresh(entry: StoredEntry): Promise<StoredEntry> {
    const now = new Date()
    const fields: Record<string, Field> = { ...entry.payload.fields }
    let changed = false
    try {
      for (const [name, field] of Object.entries(fields)) {
        switch (field.type) {
          case 'oauth':
            if (needsRefresh(field.value, now)) {
              fields[name] = { type: 'oauth', value: await refreshOAuth(field.value, now) }
              changed = true
            }
            break
          case 'secret':
          case 'text':
          case 'totp':
            break
          default:
            throw new TypeVaultError('invalid', `unexpected field ${JSON.stringify(field satisfies never)}`)
        }
      }
    } catch (error) {
      // A provider may have rotated an earlier field's refresh token already: store it before failing.
      if (changed) await this.#storeRefreshed(entry, fields)
      throw error
    }
    return changed ? this.#storeRefreshed(entry, fields) : entry
  }

  async #storeRefreshed(entry: StoredEntry, fields: Readonly<Record<string, Field>>): Promise<StoredEntry> {
    const { name, env, origin, tags } = entry.payload
    const input = {
      name,
      fields,
      tier: entry.envelope.tier,
      tags,
      ...(env === undefined ? {} : { env }),
      ...(origin === undefined ? {} : { origin }),
    }
    // A read must not promote the original writer's metadata to the reader's authority. Reuse its owner/tier
    // key when held; certificates and unavailable signing keys narrow to the entry's own tier.
    const { signer, tier } = entry.envelope
    const original =
      signer.kind === 'owner'
        ? this.#vault.keyring.owner
        : signer.kind === 'tier'
          ? await this.#vault.keyring.unlock(signer.tier)
          : undefined
    const key = original ?? (await this.#vault.keyring.unlock(tier))
    if (key === undefined) throw new TypeVaultError('denied', `no key here can refresh tier "${tier}"`)
    const refreshed = await this.#vault.put(input, signerOf(key))
    await this.#audit({ action: 'refresh', entries: [name] })
    return refreshed
  }

  #remember(value: EntryValue): EntryValue {
    for (const secret of secretValues([value])) this.#handedOut.add(secret)
    return value
  }

  async list(): Promise<readonly EntrySummary[]> {
    return (await this.#visible()).map((entry) => toSummary(valueOf(entry)))
  }

  async get(name: EntryName, reason?: string): Promise<EntryValue> {
    const entry = await this.#fresh(await this.#find(name))
    await this.#audit({ action: 'read', entries: [name], ...(reason === undefined ? {} : { reason }) })
    return this.#remember(valueOf(entry))
  }

  async values(only: readonly string[], reason?: string): Promise<readonly EntryValue[]> {
    const picked = (await this.#visible()).filter((entry) => only.length === 0 || matchesOnly(entry.payload.name, only))
    const fresh = await Promise.all(picked.map((entry) => this.#fresh(entry)))
    const names = fresh.map((entry) => entry.payload.name)
    await this.#audit({ action: 'read', entries: names, ...(reason === undefined ? {} : { reason }) })
    const own = this.#identity.ownTiers ?? []
    return fresh.map((entry) =>
      this.#remember({
        ...valueOf(entry),
        trustedWriter: writtenFromAbove(entry.envelope.signer, this.#vault.state, own),
      }),
    )
  }

  // The tier is chosen under the same exclusive lock as the write, from freshly read state, so a tier another
  // process adds in between makes the choice ambiguous instead of silently picking the old only tier.
  set(input: SetInput): Promise<EntrySummary> {
    return withLock(this.#vault.layout.lockFile, 'exclusive', async () => {
      this.#vault.refresh()
      return this.#write(input, input.tier ?? this.#identity.defaultTier ?? (await this.#onlyWritableTier()))
    })
  }

  /** Only infer when there is exactly one answer: the tier decides who can read the secret. */
  async #onlyWritableTier(): Promise<string> {
    const { state, keyring } = this.#vault
    const writable = [...(await keyring.reachableTiers())].filter((name) => allowsTier(this.#chain, state, name))
    const [only, ...others] = writable
    if (only === undefined) {
      throw new TypeVaultError('invalid', 'no tier to write to yet: create one with `typevault tier add <name>`')
    }
    if (others.length === 0) return only
    const viaEnv = this.#identity.mode === 'direct' ? ' or set TYPEVAULT_TIER' : ''
    throw new TypeVaultError('invalid', `choose a tier with --tier (one of: ${writable.join(', ')})${viaEnv}`)
  }

  async #write(input: SetInput, tier: string): Promise<EntrySummary> {
    if (
      !allowsTier(this.#chain, this.#vault.state, tier) ||
      !allowsEntry(this.#chain, this.#vault.state, tier, input.name)
    ) {
      throw new TypeVaultError('denied', `this grant cannot write ${input.name} in tier "${tier}"`)
    }
    const existing = await this.#vault.find(input.name)
    if (existing !== undefined && !this.#allows(existing)) {
      throw new TypeVaultError('denied', `the name ${input.name} is not available to this grant`)
    }
    const { ifRev } = input
    const stored = await this.#vault.put(
      entryInputOf(input, tier),
      await this.#signerFor(tier),
      ifRev === undefined ? {} : { ifRev },
    )
    await this.#audit({ action: 'write', entries: [input.name], tiers: [tier] })
    return toSummary(valueOf(stored))
  }

  // The name is resolved once and the delete targets that copy's id: resolving it again could land on a copy that
  // arrived in between (another process, or a git pull, which takes no lock), say in a tier above this scope.
  remove(name: EntryName, tier?: string): Promise<void> {
    return withLock(this.#vault.layout.lockFile, 'exclusive', async () => {
      let entry: StoredEntry | undefined
      if (tier === undefined) entry = await this.#find(name)
      else {
        const { entries } = await this.#vault.scan()
        entry = entries.find((copy) => copy.payload.name === name && copy.envelope.tier === tier)
        if (entry === undefined || !this.#allows(entry)) throw new TypeVaultError('not_found', `no entry named ${name}`)
      }
      await this.#vault.removeById(entry.envelope.id, (envelope) =>
        allowsEntry(this.#chain, this.#vault.state, envelope.tier, name),
      )
      await this.#audit({ action: 'remove', entries: [name], ...(tier === undefined ? {} : { tiers: [tier] }) })
    })
  }

  async move(from: EntryName, to: EntryName): Promise<void> {
    const entry = await this.#find(from)
    if (!allowsEntry(this.#chain, this.#vault.state, entry.envelope.tier, to)) {
      throw new TypeVaultError('denied', `this grant cannot use the name ${to}`)
    }
    await this.#vault.move(from, to, await this.#signerFor(entry.envelope.tier))
    await this.#audit({ action: 'move', entries: [from, to] })
  }

  async ownTiers(): Promise<readonly string[]> {
    return this.#identity.ownTiers ?? []
  }

  async readValues(): Promise<readonly string[]> {
    return [...this.#handedOut]
  }
}
