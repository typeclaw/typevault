import { encodeSecretKey, generateSecretKey, publicKeyOf, seal, type SecretKey } from './crypto'
import { utf8 } from './encoding'
import { signerOf } from './entries'
import { TypeVaultError } from './errors'
import { wrapPath } from './keyring'
import { withLock } from './lock'
import { rotateTier } from './rotate'
import {
  ceilingsDoc,
  type Tier,
  tiersDoc,
  includersOf,
  parseTierName,
  reach,
  signersDoc,
  type VaultState,
} from './state'
import { commitTxn, Txn } from './txn'
import type { Vault } from './vault'

/** Owner-only changes to tiers, signers and ceilings. Each one lands as a single transaction. */
export class Admin {
  readonly #vault: Vault
  readonly #owner: SecretKey

  constructor(vault: Vault) {
    const owner = vault.keyring.owner
    if (owner === undefined) throw new TypeVaultError('denied', 'this needs the owner key')
    this.#vault = vault
    this.#owner = owner
  }

  #mutate(build: (state: VaultState, txn: Txn) => Promise<void>): Promise<void> {
    return withLock(this.#vault.layout.lockFile, 'exclusive', async () => {
      this.#vault.refresh()
      const txn = new Txn()
      await build(this.#vault.state, txn)
      commitTxn(this.#vault.layout, txn)
      this.#vault.refresh()
    })
  }

  async #wrapFor(txn: Txn, included: string, state: VaultState, holder: { name: string; tier: Tier }): Promise<void> {
    const key = await this.#vault.keyring.unlock(included)
    const meta = state.tiers[included]
    if (key === undefined || meta === undefined)
      throw new TypeVaultError('not_found', `cannot unlock tier "${included}"`)
    const sealed = await seal([holder.tier.recipient], utf8(encodeSecretKey(key)))
    txn.put(wrapPath(included, meta.gen, { kind: 'tier', tier: holder.name, gen: holder.tier.gen }), sealed)
  }

  addTier(rawName: string): Promise<void> {
    const name = parseTierName(rawName)
    return this.#mutate(async (state, txn) => {
      if (state.tiers[name] !== undefined) throw new TypeVaultError('conflict', `tier "${name}" already exists`)
      const key = await generateSecretKey({ kind: 'tier', tier: name, gen: 1 })
      const tier: Tier = { includes: [], gen: 1, ...(await publicKeyOf(key)) }
      txn.put(wrapPath(name, 1, { kind: 'owner' }), await seal([state.owner.recipient], utf8(encodeSecretKey(key))))
      txn.put('tiers.json', tiersDoc({ ...state.tiers, [name]: tier }, this.#owner, state.seqs.tiers + 1))
    })
  }

  removeTier(name: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      if (state.tiers[name] === undefined) throw new TypeVaultError('not_found', `no tier "${name}"`)
      if (includersOf(state.tiers, name).length > 0)
        throw new TypeVaultError('conflict', `other tiers include "${name}"`)
      const { entries } = await this.#vault.scan()
      if (entries.some((entry) => entry.envelope.tier === name)) {
        throw new TypeVaultError('conflict', `tier "${name}" still has entries`)
      }
      const { [name]: _removed, ...rest } = state.tiers
      for (const included of state.tiers[name]?.includes ?? []) {
        const gen = state.tiers[included]?.gen ?? 0
        txn.remove(wrapPath(included, gen, { kind: 'tier', tier: name, gen: state.tiers[name]?.gen ?? 0 }))
      }
      txn.remove(`tiers/${name}`)
      txn.put('tiers.json', tiersDoc(rest, this.#owner, state.seqs.tiers + 1))
    })
  }

  include(tier: string, included: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      const holder = state.tiers[tier]
      if (holder === undefined || state.tiers[included] === undefined)
        throw new TypeVaultError('not_found', 'no such tier')
      if (holder.includes.includes(included)) return
      if (reach(state.tiers, included).has(tier)) {
        throw new TypeVaultError('invalid', `"${included}" already reaches "${tier}"; including it would form a cycle`)
      }
      await this.#wrapFor(txn, included, state, { name: tier, tier: holder })
      const updated = { ...holder, includes: [...holder.includes, included] }
      txn.put('tiers.json', tiersDoc({ ...state.tiers, [tier]: updated }, this.#owner, state.seqs.tiers + 1))
    })
  }

  /** Drops an include, then rotates the included tier so the old wrap stops working. */
  async exclude(tier: string, included: string): Promise<readonly string[]> {
    await this.#mutate(async (state, txn) => {
      const holder = state.tiers[tier]
      if (holder === undefined || !holder.includes.includes(included)) {
        throw new TypeVaultError('not_found', `"${tier}" does not include "${included}"`)
      }
      const meta = state.tiers[included]
      txn.remove(wrapPath(included, meta?.gen ?? 0, { kind: 'tier', tier, gen: holder.gen }))
      const updated = { ...holder, includes: holder.includes.filter((name) => name !== included) }
      txn.put('tiers.json', tiersDoc({ ...state.tiers, [tier]: updated }, this.#owner, state.seqs.tiers + 1))
    })
    return this.rotate(included)
  }

  /** New key generation for `name`. Returns the names of every entry it could reach, now flagged for rotation. */
  async rotate(name: string): Promise<readonly string[]> {
    let affected: readonly string[] = []
    await this.#mutate(async (state, txn) => {
      affected = await rotateTier({ vault: this.#vault, owner: this.#owner, state, txn }, name)
    })
    return affected
  }

  setSigner(id: string, signPublic: string, tiers: readonly string[]): Promise<void> {
    return this.#mutate(async (state, txn) => {
      txn.put(
        'signers.json',
        signersDoc({ ...state.signers, [id]: { signPublic, tiers } }, this.#owner, state.seqs.signers + 1),
      )
    })
  }

  removeSigner(id: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      const { [id]: _removed, ...rest } = state.signers
      txn.put('signers.json', signersDoc(rest, this.#owner, state.seqs.signers + 1))
    })
  }

  setCeiling(name: string, tier: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      if (state.tiers[tier] === undefined) throw new TypeVaultError('not_found', `no tier "${tier}"`)
      txn.put(
        'ceilings.json',
        ceilingsDoc({ ...state.ceilings, [parseTierName(name)]: tier }, this.#owner, state.seqs.ceilings + 1),
      )
    })
  }

  removeCeiling(name: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      const { [name]: _removed, ...rest } = state.ceilings
      txn.put('ceilings.json', ceilingsDoc(rest, this.#owner, state.seqs.ceilings + 1))
    })
  }

  async exportKey(tier: string): Promise<string> {
    const key = await this.#vault.keyring.unlock(tier)
    if (key === undefined) throw new TypeVaultError('not_found', `no tier "${tier}"`)
    return encodeSecretKey(key)
  }

  exportOwnerKey(): string {
    return encodeSecretKey(this.#owner)
  }

  get signer(): ReturnType<typeof signerOf> {
    return signerOf(this.#owner)
  }
}
