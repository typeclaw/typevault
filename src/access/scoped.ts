import { appendAudit, type AuditEvent, type AuditMode } from '../audit/log'
import { signerOf } from '../core/entries'
import { TypeVaultError } from '../core/errors'
import { withLock } from '../core/lock'
import { type EntryName, matchesOnly } from '../core/naming'
import { resolveName, type StoredEntry, type Vault } from '../core/vault'
import { needsRefresh, refreshOAuth } from '../oauth/refresh'
import { allowsEntry, allowsGroup, type ScopeChain } from './scope'
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
  /** Groups held directly; see `Access.ownGroups`. */
  readonly ownGroups?: readonly string[]
  /** Group used by `set` when the caller names none. */
  readonly defaultGroup?: string
}

const valueOf = (entry: StoredEntry): EntryValue =>
  toValue(entry.envelope.group, entry.envelope.id, entry.envelope.rev, entry.payload)

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
    return allowsEntry(this.#chain, this.#vault.state, entry.envelope.group, entry.payload.name)
  }

  /** One entry per name: the copy each name resolves to within this scope (see `resolveName`). */
  async #visible(): Promise<readonly StoredEntry[]> {
    const { entries } = await this.#vault.scan()
    const byName = Map.groupBy(
      entries.filter((entry) => this.#allows(entry)),
      (entry) => entry.payload.name,
    )
    return [...byName.values()].flatMap((copies) => resolveName(this.#vault.state.groups, copies) ?? [])
  }

  async #find(name: EntryName): Promise<StoredEntry> {
    const entry = await this.#vault.find(name)
    if (entry === undefined || !this.#allows(entry)) throw new TypeVaultError('not_found', `no entry named ${name}`)
    return entry
  }

  async #signerFor(group: string): Promise<ReturnType<typeof signerOf>> {
    // Direct mode is the key holder acting itself, so the owner signs as the owner. The daemon writes on behalf
    // of grants and signs with the group's own key, so a grant's writes never look owner-authored.
    const owner = this.#identity.mode === 'direct' ? this.#vault.keyring.owner : undefined
    const key = owner ?? (await this.#vault.keyring.unlock(group)) ?? this.#vault.keyring.owner
    if (key === undefined) throw new TypeVaultError('denied', `no key here can write group "${group}"`)
    return signerOf(key)
  }

  /** OAuth entries past their expiry are refreshed and written back before anyone reads them. */
  async #fresh(entry: StoredEntry): Promise<StoredEntry> {
    const now = new Date()
    if (entry.payload.type !== 'oauth' || !needsRefresh(entry.payload.fields, now)) return entry
    const fields = await refreshOAuth(entry.payload.fields, now)
    const { name, type, env, origin, tags } = entry.payload
    const input = {
      name,
      type,
      fields,
      group: entry.envelope.group,
      tags,
      ...(env === undefined ? {} : { env }),
      ...(origin === undefined ? {} : { origin }),
    }
    const refreshed = await this.#vault.put(input, await this.#signerFor(entry.envelope.group))
    await this.#audit({ action: 'refresh', entries: [name] })
    return refreshed
  }

  #remember(value: EntryValue): EntryValue {
    for (const field of Object.values(value.fields)) if (field !== '') this.#handedOut.add(field)
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
    const own = this.#identity.ownGroups ?? []
    return fresh.map((entry) =>
      this.#remember({
        ...valueOf(entry),
        trustedWriter: writtenFromAbove(entry.envelope.signer, this.#vault.state, own),
      }),
    )
  }

  // The group is chosen under the same exclusive lock as the write, from freshly read state, so a group another
  // process adds in between makes the choice ambiguous instead of silently picking the old only group.
  set(input: SetInput): Promise<EntrySummary> {
    return withLock(this.#vault.layout.lockFile, 'exclusive', async () => {
      this.#vault.refresh()
      return this.#write(input, input.group ?? this.#identity.defaultGroup ?? (await this.#onlyWritableGroup()))
    })
  }

  /** Only infer when there is exactly one answer: the group decides who can read the secret. */
  async #onlyWritableGroup(): Promise<string> {
    const { state, keyring } = this.#vault
    const writable = [...(await keyring.reachableGroups())].filter((name) => allowsGroup(this.#chain, state, name))
    const [only, ...others] = writable
    if (only === undefined) {
      throw new TypeVaultError('invalid', 'no group to write to yet: create one with `typevault group add <name>`')
    }
    if (others.length === 0) return only
    const viaEnv = this.#identity.mode === 'direct' ? ' or set TYPEVAULT_GROUP' : ''
    throw new TypeVaultError('invalid', `choose a group with --group (one of: ${writable.join(', ')})${viaEnv}`)
  }

  async #write(input: SetInput, group: string): Promise<EntrySummary> {
    if (
      !allowsGroup(this.#chain, this.#vault.state, group) ||
      !allowsEntry(this.#chain, this.#vault.state, group, input.name)
    ) {
      throw new TypeVaultError('denied', `this grant cannot write ${input.name} in group "${group}"`)
    }
    const existing = await this.#vault.find(input.name)
    if (existing !== undefined && !this.#allows(existing)) {
      throw new TypeVaultError('denied', `the name ${input.name} is not available to this grant`)
    }
    const { ifRev } = input
    const stored = await this.#vault.put(
      entryInputOf(input, group),
      await this.#signerFor(group),
      ifRev === undefined ? {} : { ifRev },
    )
    await this.#audit({ action: 'write', entries: [input.name], groups: [group] })
    return toSummary(valueOf(stored))
  }

  async remove(name: EntryName, group?: string): Promise<void> {
    if (group === undefined) await this.#find(name)
    else if (!allowsEntry(this.#chain, this.#vault.state, group, name)) {
      throw new TypeVaultError('not_found', `no entry named ${name}`)
    }
    await this.#vault.remove(name, group)
    await this.#audit({ action: 'remove', entries: [name], ...(group === undefined ? {} : { groups: [group] }) })
  }

  async move(from: EntryName, to: EntryName): Promise<void> {
    const entry = await this.#find(from)
    if (!allowsEntry(this.#chain, this.#vault.state, entry.envelope.group, to)) {
      throw new TypeVaultError('denied', `this grant cannot use the name ${to}`)
    }
    await this.#vault.move(from, to, await this.#signerFor(entry.envelope.group))
    await this.#audit({ action: 'move', entries: [from, to] })
  }

  async ownGroups(): Promise<readonly string[]> {
    return this.#identity.ownGroups ?? []
  }

  async readValues(): Promise<readonly string[]> {
    return [...this.#handedOut]
  }
}
