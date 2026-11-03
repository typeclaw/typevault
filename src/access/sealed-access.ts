import { existsSync } from 'node:fs'

import { appendAudit, type AuditEvent } from '../audit/log'
import { TypeVaultError } from '../core/errors'
import type { Layout } from '../core/layout'
import { type EntryName, matchesOnly } from '../core/naming'
import { Vault } from '../core/vault'
import { allowsEntry } from './scope'
import { type SealedBundle, sealedSigningSecret } from './sealed'
import { type Access, type EntrySummary, type EntryValue, entryInputOf, type SetInput, toSummary } from './types'

type Env = Readonly<Record<string, string | undefined>>

/**
 * Access backed by a sealed grant: reads come from the bundle, writes go straight to the vault directory
 * signed with the grant's certificate. Expiry is advisory (the bytes stay decryptable) but always enforced here.
 */
export class SealedAccess implements Access {
  readonly #bundle: SealedBundle
  readonly #layout: Layout | undefined
  readonly #env: Env

  /** `layout` is undefined where no vault is selected: reads still work, writes refuse. */
  constructor(bundle: SealedBundle, layout: Layout | undefined, env: Env) {
    this.#bundle = bundle
    this.#layout = layout
    this.#env = env
  }

  #live(): SealedBundle {
    if (Date.parse(this.#bundle.exp) <= Date.now()) throw new TypeVaultError('expired', 'this sealed grant has expired')
    return this.#bundle
  }

  #entry(name: EntryName): EntryValue {
    const entry = this.#live().entries.find((value) => value.name === name)
    if (entry === undefined) throw new TypeVaultError('not_found', `no entry named ${name}`)
    return entry
  }

  async #vault(): Promise<Vault> {
    if (this.#layout === undefined || !existsSync(this.#layout.operatorFile)) {
      throw new TypeVaultError('unavailable', 'writing with a sealed grant needs the vault directory')
    }
    return Vault.open(this.#layout, [], this.#env)
  }

  /** Best effort: a sealed grant may run where no vault directory exists. */
  async #audit(event: Omit<AuditEvent, 'mode' | 'grant' | 'label'>): Promise<void> {
    const layout = this.#layout
    if (layout === undefined || !existsSync(layout.operatorFile)) return
    await appendAudit(layout, { ...event, mode: 'sealed', grant: this.#bundle.id, label: this.#bundle.label })
  }

  async list(): Promise<readonly EntrySummary[]> {
    return this.#live().entries.map(toSummary)
  }

  async get(name: EntryName, reason?: string): Promise<EntryValue> {
    const entry = this.#entry(name)
    await this.#audit({ action: 'read', entries: [name], ...(reason === undefined ? {} : { reason }) })
    return entry
  }

  async values(only: readonly string[], reason?: string): Promise<readonly EntryValue[]> {
    const picked = this.#live().entries.filter((value) => only.length === 0 || matchesOnly(value.name, only))
    await this.#audit({
      action: 'read',
      entries: picked.map((value) => value.name),
      ...(reason === undefined ? {} : { reason }),
    })
    return picked
  }

  async set(input: SetInput): Promise<EntrySummary> {
    const bundle = this.#live()
    const vault = await this.#vault()
    const group = input.group ?? bundle.scope.groups[0]
    if (group === undefined || !allowsEntry([bundle.scope], vault.state, group, input.name)) {
      throw new TypeVaultError('denied', `this grant cannot write ${input.name} in group "${group ?? '?'}"`)
    }
    const prior = bundle.entries.find((value) => value.name === input.name)
    const { ifRev } = input
    const stored = await vault.put(
      entryInputOf(input, group),
      { ref: { kind: 'cert', cert: bundle.write.cert }, signSecret: sealedSigningSecret(bundle) },
      { ...(ifRev === undefined ? {} : { ifRev }), ...(prior === undefined ? {} : { base: prior }) },
    )
    await this.#audit({ action: 'write', entries: [input.name], groups: [group] })
    const { envelope, payload } = stored
    return {
      name: payload.name,
      type: payload.type,
      group,
      rev: envelope.rev,
      tags: payload.tags,
      rotated: payload.rotated,
      needsRotation: false,
    }
  }

  async remove(name: EntryName, _group?: string): Promise<void> {
    const entry = this.#entry(name)
    await (await this.#vault()).removeById(entry.id)
    await this.#audit({ action: 'remove', entries: [name] })
  }

  async move(from: EntryName, to: EntryName): Promise<void> {
    const entry = this.#entry(from)
    await this.set({ name: to, type: entry.type, fields: entry.fields, group: entry.group, tags: entry.tags })
    await this.remove(from)
  }

  async ownGroups(): Promise<readonly string[]> {
    return this.#bundle.scope.groups
  }

  async readValues(): Promise<readonly string[]> {
    return this.#bundle.entries.flatMap((value) => Object.values(value.fields).filter((field) => field !== ''))
  }
}
