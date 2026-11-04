import { existsSync } from 'node:fs'

import { appendAudit, type AuditEvent } from '../audit/log'
import { signerAuthority } from '../core/entries'
import { TypeVaultError } from '../core/errors'
import type { Layout } from '../core/layout'
import { type EntryName, matchesOnly } from '../core/naming'
import { Vault } from '../core/vault'
import { secretValues } from './env'
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
    if (this.#layout === undefined || !existsSync(this.#layout.ownerFile)) {
      throw new TypeVaultError('unavailable', 'writing with a sealed grant needs the vault directory')
    }
    return Vault.open(this.#layout, [], this.#env)
  }

  /** Best effort: a sealed grant may run where no vault directory exists. */
  async #audit(event: Omit<AuditEvent, 'mode' | 'grant' | 'label'>): Promise<void> {
    const layout = this.#layout
    if (layout === undefined || !existsSync(layout.ownerFile)) return
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
    const prior = bundle.entries.find((value) => value.name === input.name)
    const tier = input.tier ?? prior?.tier ?? bundle.scope.tiers[0]
    if (tier === undefined || !allowsEntry([bundle.scope], vault.state, tier, input.name)) {
      throw new TypeVaultError('denied', `this grant cannot write ${input.name} in tier "${tier ?? '?'}"`)
    }
    // Blind writes can't remove the old copy (that takes reading it), so moving tiers would leave two.
    if (prior !== undefined && prior.tier !== tier) {
      throw new TypeVaultError('denied', `${input.name} is in tier "${prior.tier}"; a sealed grant cannot move it`)
    }
    const { ifRev } = input
    const stored = await vault.put(
      entryInputOf(input, tier),
      { ref: { kind: 'cert', cert: bundle.write.cert }, signSecret: sealedSigningSecret(bundle) },
      { ...(ifRev === undefined ? {} : { ifRev }), ...(prior === undefined ? {} : { base: prior }) },
    )
    await this.#audit({ action: 'write', entries: [input.name], tiers: [tier] })
    const { envelope, payload } = stored
    return {
      name: payload.name,
      tier,
      rev: envelope.rev,
      tags: payload.tags,
      rotated: payload.rotated,
      needsRotation: false,
    }
  }

  /**
   * The bundle is holder-editable (whoever holds the grant can re-seal it), so only the issuer-signed
   * certificate bounds what may be deleted: its tiers, `--only` and expiry, checked against the file on disk.
   * The entry must still be the revision this grant carried, or one this grant's certificate wrote since.
   */
  async remove(name: EntryName, _tier?: string): Promise<void> {
    const entry = this.#entry(name)
    const { cert } = this.#bundle.write
    const vault = await this.#vault()
    await vault.removeById(
      entry.id,
      (envelope) =>
        envelope.tier === entry.tier &&
        (envelope.rev === entry.rev ||
          (envelope.signer.kind === 'cert' && envelope.signer.cert.signPublic === cert.signPublic)) &&
        allowsEntry([{ tiers: cert.tiers, only: cert.only }], vault.state, envelope.tier, name) &&
        signerAuthority({ kind: 'cert', cert }, envelope.tier, vault.state, new Date().toISOString()) !== undefined,
    )
    await this.#audit({ action: 'remove', entries: [name] })
  }

  async move(from: EntryName, to: EntryName): Promise<void> {
    const entry = this.#entry(from)
    await this.set({ name: to, fields: entry.fields, tier: entry.tier, tags: entry.tags })
    await this.remove(from)
  }

  async ownTiers(): Promise<readonly string[]> {
    return this.#bundle.scope.tiers
  }

  async readValues(): Promise<readonly string[]> {
    return secretValues(this.#bundle.entries)
  }
}
