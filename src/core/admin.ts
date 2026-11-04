import { encodeSecretKey, generateSecretKey, type PublicKey, publicKeyOf, seal, type SecretKey } from './crypto'
import { utf8 } from './encoding'
import { signerOf } from './entries'
import { TypeVaultError } from './errors'
import { ownerWrapPath, wrapPath } from './keyring'
import { withLock } from './lock'
import { rotateTiers } from './rotate'
import {
  ceilingsDoc,
  type MemberKind,
  membersDoc,
  type Tier,
  tiersDoc,
  includersOf,
  parseMemberName,
  parseTierName,
  reach,
  signersDoc,
  type VaultState,
} from './state'
import { commitTxn, Txn } from './txn'
import type { Vault } from './vault'

export type NewMember = PublicKey & {
  readonly kind: MemberKind
  readonly owner: boolean
  readonly tiers: readonly string[]
}

/** Every tier `tiers` reach: rotating all of them keeps old generations out of a member's hands. */
const reachOf = (state: VaultState, tiers: readonly string[]): readonly string[] =>
  [...new Set(tiers.flatMap((tier) => [...reach(state.tiers, tier)]))].sort()

/** Owner-only changes to tiers, members, signers and ceilings. Each one lands as a single transaction. */
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
      const holders = Object.entries(state.members).filter(([, member]) => member.tiers.includes(name))
      if (holders.length > 0) {
        const names = holders.map(([member]) => member).join(', ')
        throw new TypeVaultError('conflict', `members still hold "${name}": ${names}`)
      }
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

  /**
   * Makes `tier` include `included`, rotating every tier `included` reaches in the same transaction, so the includer
   * can open neither their older ciphertext in git history nor entries deleted before the include.
   */
  include(tier: string, included: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      const holder = state.tiers[tier]
      if (holder === undefined || state.tiers[included] === undefined)
        throw new TypeVaultError('not_found', 'no such tier')
      if (holder.includes.includes(included)) return
      if (reach(state.tiers, included).has(tier)) {
        throw new TypeVaultError('invalid', `"${included}" already reaches "${tier}"; including it would form a cycle`)
      }
      const tiers = { ...state.tiers, [tier]: { ...holder, includes: [...holder.includes, included] } }
      const context = { vault: this.#vault, owner: this.#owner, state: { ...state, tiers }, txn, exposed: false }
      await rotateTiers(context, reachOf(state, [included]))
    })
  }

  /**
   * Drops an include and rotates the included tier in one transaction: a crash leaves both or neither, never a
   * dropped include whose old wrap still opens the included tier.
   */
  async exclude(tier: string, included: string): Promise<readonly string[]> {
    let affected: readonly string[] = []
    await this.#mutate(async (state, txn) => {
      const holder = state.tiers[tier]
      if (holder === undefined || !holder.includes.includes(included)) {
        throw new TypeVaultError('not_found', `"${tier}" does not include "${included}"`)
      }
      const updated = { ...holder, includes: holder.includes.filter((name) => name !== included) }
      // Rotating removes the included tier's old generation, the dropped wrap with it, and rewrites tiers.json.
      const context = { vault: this.#vault, owner: this.#owner, txn, exposed: true }
      affected = await rotateTiers({ ...context, state: { ...state, tiers: { ...state.tiers, [tier]: updated } } }, [
        included,
      ])
    })
    return affected
  }

  /** New key generation for `name`. Returns the names of every entry it could reach, now flagged for rotation. */
  async rotate(name: string): Promise<readonly string[]> {
    let affected: readonly string[] = []
    await this.#mutate(async (state, txn) => {
      affected = await rotateTiers({ vault: this.#vault, owner: this.#owner, state, txn, exposed: true }, [name])
    })
    return affected
  }

  /**
   * Lists a member and wraps the owner key (for owners) and their tiers' keys to them. Every tier they reach is
   * rotated in the same transaction, so they can open neither older ciphertext in git history nor entries deleted
   * before they joined.
   */
  addMember(rawName: string, member: NewMember): Promise<void> {
    const name = parseMemberName(rawName)
    return this.#mutate(async (state, txn) => {
      if (state.members[name] !== undefined) throw new TypeVaultError('conflict', `member "${name}" already exists`)
      const unknown = member.tiers.find((tier) => state.tiers[tier] === undefined)
      if (unknown !== undefined) throw new TypeVaultError('not_found', `no tier "${unknown}"`)
      const { kind, recipient, signPublic, owner, tiers } = member
      const members = { ...state.members, [name]: { kind, recipient, signPublic, owner, tiers: [...tiers] } }
      if (owner) txn.put(ownerWrapPath(name), await seal([recipient], utf8(encodeSecretKey(this.#owner))))
      txn.put('members.json', membersDoc(members, this.#owner, state.seqs.members + 1))
      const context = { vault: this.#vault, owner: this.#owner, state: { ...state, members }, txn, exposed: false }
      await rotateTiers(context, reachOf(state, tiers))
    })
  }

  /**
   * Drops a member and rotates every tier they reached, in one transaction: a crash leaves both or neither, never a
   * removed member whose keys still open new ciphertext. Returns the entries they could read, now flagged for
   * rotation: what they already decrypted can only be revoked at each secret's source.
   */
  async removeMember(name: string): Promise<readonly string[]> {
    let affected: readonly string[] = []
    await this.#mutate(async (state, txn) => {
      const member = state.members[name]
      if (member === undefined) throw new TypeVaultError('not_found', `no member "${name}"`)
      // Every entry is also sealed to the owner key, which can't be rotated yet: a former owner would keep reading.
      if (member.owner) throw new TypeVaultError('invalid', `"${name}" is an owner; removing an owner is not supported`)
      const { [name]: _removed, ...rest } = state.members
      txn.remove(`members/${name}.key`)
      txn.put('members.json', membersDoc(rest, this.#owner, state.seqs.members + 1))
      const context = { vault: this.#vault, owner: this.#owner, state: { ...state, members: rest }, txn, exposed: true }
      affected = await rotateTiers(context, reachOf(state, member.tiers))
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

  get signer(): ReturnType<typeof signerOf> {
    return signerOf(this.#owner)
  }
}
