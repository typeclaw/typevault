import { encodeSecretKey, generateSecretKey, publicKeyOf, seal, type SecretKey } from './crypto'
import { utf8 } from './encoding'
import { signerOf } from './entries'
import { TypeVaultError } from './errors'
import { wrapPath } from './keyring'
import { withLock } from './lock'
import { rotateGroup } from './rotate'
import {
  ceilingsDoc,
  type Group,
  groupsDoc,
  includersOf,
  parseGroupName,
  reach,
  signersDoc,
  type VaultState,
} from './state'
import { commitTxn, Txn } from './txn'
import type { Vault } from './vault'

/** Operator-only changes to groups, signers and ceilings. Each one lands as a single transaction. */
export class Admin {
  readonly #vault: Vault
  readonly #operator: SecretKey

  constructor(vault: Vault) {
    const operator = vault.keyring.operator
    if (operator === undefined) throw new TypeVaultError('denied', 'this needs the operator key')
    this.#vault = vault
    this.#operator = operator
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

  async #wrapFor(txn: Txn, included: string, state: VaultState, holder: { name: string; group: Group }): Promise<void> {
    const key = await this.#vault.keyring.unlock(included)
    const meta = state.groups[included]
    if (key === undefined || meta === undefined)
      throw new TypeVaultError('not_found', `cannot unlock group "${included}"`)
    const sealed = await seal([holder.group.recipient], utf8(encodeSecretKey(key)))
    txn.put(wrapPath(included, meta.gen, { kind: 'group', group: holder.name, gen: holder.group.gen }), sealed)
  }

  addGroup(rawName: string): Promise<void> {
    const name = parseGroupName(rawName)
    return this.#mutate(async (state, txn) => {
      if (state.groups[name] !== undefined) throw new TypeVaultError('conflict', `group "${name}" already exists`)
      const key = await generateSecretKey({ kind: 'group', group: name, gen: 1 })
      const group: Group = { includes: [], gen: 1, ...(await publicKeyOf(key)) }
      txn.put(
        wrapPath(name, 1, { kind: 'operator' }),
        await seal([state.operator.recipient], utf8(encodeSecretKey(key))),
      )
      txn.put('groups.json', groupsDoc({ ...state.groups, [name]: group }, this.#operator, state.seqs.groups + 1))
    })
  }

  removeGroup(name: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      if (state.groups[name] === undefined) throw new TypeVaultError('not_found', `no group "${name}"`)
      if (includersOf(state.groups, name).length > 0)
        throw new TypeVaultError('conflict', `other groups include "${name}"`)
      const { entries } = await this.#vault.scan()
      if (entries.some((entry) => entry.envelope.group === name)) {
        throw new TypeVaultError('conflict', `group "${name}" still has entries`)
      }
      const { [name]: _removed, ...rest } = state.groups
      for (const included of state.groups[name]?.includes ?? []) {
        const gen = state.groups[included]?.gen ?? 0
        txn.remove(wrapPath(included, gen, { kind: 'group', group: name, gen: state.groups[name]?.gen ?? 0 }))
      }
      txn.remove(`groups/${name}`)
      txn.put('groups.json', groupsDoc(rest, this.#operator, state.seqs.groups + 1))
    })
  }

  include(group: string, included: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      const holder = state.groups[group]
      if (holder === undefined || state.groups[included] === undefined)
        throw new TypeVaultError('not_found', 'no such group')
      if (holder.includes.includes(included)) return
      if (reach(state.groups, included).has(group)) {
        throw new TypeVaultError('invalid', `"${included}" already reaches "${group}"; including it would form a cycle`)
      }
      await this.#wrapFor(txn, included, state, { name: group, group: holder })
      const updated = { ...holder, includes: [...holder.includes, included] }
      txn.put('groups.json', groupsDoc({ ...state.groups, [group]: updated }, this.#operator, state.seqs.groups + 1))
    })
  }

  /** Drops an include, then rotates the included group so the old wrap stops working. */
  async exclude(group: string, included: string): Promise<readonly string[]> {
    await this.#mutate(async (state, txn) => {
      const holder = state.groups[group]
      if (holder === undefined || !holder.includes.includes(included)) {
        throw new TypeVaultError('not_found', `"${group}" does not include "${included}"`)
      }
      const meta = state.groups[included]
      txn.remove(wrapPath(included, meta?.gen ?? 0, { kind: 'group', group, gen: holder.gen }))
      const updated = { ...holder, includes: holder.includes.filter((name) => name !== included) }
      txn.put('groups.json', groupsDoc({ ...state.groups, [group]: updated }, this.#operator, state.seqs.groups + 1))
    })
    return this.rotate(included)
  }

  /** New key generation for `name`. Returns the names of every entry it could reach, now flagged for rotation. */
  async rotate(name: string): Promise<readonly string[]> {
    let affected: readonly string[] = []
    await this.#mutate(async (state, txn) => {
      affected = await rotateGroup({ vault: this.#vault, operator: this.#operator, state, txn }, name)
    })
    return affected
  }

  setSigner(id: string, signPublic: string, groups: readonly string[]): Promise<void> {
    return this.#mutate(async (state, txn) => {
      txn.put(
        'signers.json',
        signersDoc({ ...state.signers, [id]: { signPublic, groups } }, this.#operator, state.seqs.signers + 1),
      )
    })
  }

  removeSigner(id: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      const { [id]: _removed, ...rest } = state.signers
      txn.put('signers.json', signersDoc(rest, this.#operator, state.seqs.signers + 1))
    })
  }

  setCeiling(name: string, group: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      if (state.groups[group] === undefined) throw new TypeVaultError('not_found', `no group "${group}"`)
      txn.put(
        'ceilings.json',
        ceilingsDoc({ ...state.ceilings, [parseGroupName(name)]: group }, this.#operator, state.seqs.ceilings + 1),
      )
    })
  }

  removeCeiling(name: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      const { [name]: _removed, ...rest } = state.ceilings
      txn.put('ceilings.json', ceilingsDoc(rest, this.#operator, state.seqs.ceilings + 1))
    })
  }

  async exportKey(group: string): Promise<string> {
    const key = await this.#vault.keyring.unlock(group)
    if (key === undefined) throw new TypeVaultError('not_found', `no group "${group}"`)
    return encodeSecretKey(key)
  }

  get signer(): ReturnType<typeof signerOf> {
    return signerOf(this.#operator)
  }
}
