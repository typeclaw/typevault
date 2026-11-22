import { encodeSecretKey, generateSecretKey, type PublicKey, publicKeyOf, seal, type SecretKey } from './crypto'
import { fromBase64, utf8 } from './encoding'
import { signerOf } from './entries'
import { TypeVaultError } from './errors'
import { decodeMemberPublic } from './identity'
import { ownerWrapPath, wrapPath } from './keyring'
import { withLock } from './lock'
import { rotateOwner, rotateTiers } from './rotate'
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

  #mutate<T>(build: (state: VaultState, txn: Txn) => Promise<T>): Promise<T> {
    return withLock(this.#vault.layout.lockFile, 'exclusive', async () => {
      this.#vault.refresh()
      const txn = new Txn()
      const result = await build(this.#vault.state, txn)
      commitTxn(this.#vault.layout, txn)
      this.#vault.reload()
      return result
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
  exclude(tier: string, included: string): Promise<readonly string[]> {
    return this.#mutate(async (state, txn) => {
      const holder = state.tiers[tier]
      if (holder === undefined || !holder.includes.includes(included)) {
        throw new TypeVaultError('not_found', `"${tier}" does not include "${included}"`)
      }
      const updated = { ...holder, includes: holder.includes.filter((name) => name !== included) }
      // Rotating removes the included tier's old generation, the dropped wrap with it, and rewrites tiers.json.
      const context = { vault: this.#vault, owner: this.#owner, txn, exposed: true }
      return rotateTiers({ ...context, state: { ...state, tiers: { ...state.tiers, [tier]: updated } } }, [included])
    })
  }

  /** Rotates every tier `name` reaches. Returns their entry names, now flagged for rotation at the source. */
  rotate(name: string): Promise<readonly string[]> {
    return this.#mutate(async (state, txn) =>
      rotateTiers({ vault: this.#vault, owner: this.#owner, state, txn, exposed: true }, reachOf(state, [name])),
    )
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
      // One key under two names would survive removing either name.
      const alias = Object.entries(state.members).find(([, other]) => other.recipient === recipient)
      if (alias !== undefined) throw new TypeVaultError('conflict', `this key is already member "${alias[0]}"`)
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
   * rotation: what they already decrypted can only be revoked at each secret's source. Any other name listing the same
   * key goes too: it would otherwise keep that key's access.
   */
  removeMember(name: string): Promise<readonly string[]> {
    return this.#mutate(async (state, txn) => {
      const member = state.members[name]
      if (member === undefined) throw new TypeVaultError('not_found', `no member "${name}"`)
      const removed = Object.entries(state.members).filter(([, other]) => other.recipient === member.recipient)
      const members = Object.fromEntries(
        Object.entries(state.members).filter(([, other]) => other.recipient !== member.recipient),
      )
      const context = { vault: this.#vault, owner: this.#owner, state: { ...state, members }, txn, exposed: true }
      for (const [gone] of removed) txn.remove(`members/${gone}.key`)
      if (removed.some(([, gone]) => gone.owner)) {
        if (!Object.values(members).some((remaining) => remaining.owner)) {
          throw new TypeVaultError('invalid', `"${name}" is the last owner; add another owner first`)
        }
        for (const [gone, { owner }] of removed) if (owner) txn.remove(ownerWrapPath(gone))
        return rotateOwner(context)
      }
      txn.put('members.json', membersDoc(members, this.#owner, state.seqs.members + 1))
      return rotateTiers(
        context,
        reachOf(
          state,
          removed.flatMap(([, gone]) => gone.tiers),
        ),
      )
    })
  }

  async setSigner(id: string, signPublic: string, tiers: readonly string[]): Promise<void> {
    const name = parseTierName(id)
    let key: Uint8Array
    try {
      key = fromBase64(signPublic)
    } catch (error) {
      if (error instanceof Error) throw new TypeVaultError('invalid', 'signer public key is not valid base64')
      throw error
    }
    if (key.length !== 32) throw new TypeVaultError('invalid', 'signer public key must be 32 bytes')
    if (tiers.length === 0) throw new TypeVaultError('invalid', 'signer needs at least one tier')
    await this.#mutate(async (state, txn) => {
      const unknown = tiers.find((tier) => tier !== '*' && state.tiers[tier] === undefined)
      if (unknown !== undefined) throw new TypeVaultError('not_found', `no tier "${unknown}"`)
      txn.put(
        'signers.json',
        signersDoc({ ...state.signers, [name]: { signPublic, tiers } }, this.#owner, state.seqs.signers + 1),
      )
    })
  }

  removeSigner(id: string): Promise<void> {
    return this.#mutate(async (state, txn) => {
      if (state.signers[id] === undefined) throw new TypeVaultError('not_found', `no signer "${id}"`)
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
      if (state.ceilings[name] === undefined) throw new TypeVaultError('not_found', `no ceiling "${name}"`)
      const { [name]: _removed, ...rest } = state.ceilings
      txn.put('ceilings.json', ceilingsDoc(rest, this.#owner, state.seqs.ceilings + 1))
    })
  }

  get signer(): ReturnType<typeof signerOf> {
    return signerOf(this.#owner)
  }
}

/** One owner change, as the CLI asks it: run here in direct mode, or by an unlocked session's daemon. */
export type AdminOp =
  | {
      readonly op: 'tier.add' | 'tier.rm' | 'key.rotate' | 'ceiling.rm' | 'signer.rm' | 'member.rm'
      readonly name: string
    }
  | { readonly op: 'tier.include' | 'tier.exclude'; readonly tier: string; readonly included: string }
  | { readonly op: 'ceiling.set'; readonly name: string; readonly tier: string }
  | { readonly op: 'signer.add'; readonly id: string; readonly publicKey: string; readonly tiers: readonly string[] }
  | {
      readonly op: 'member.add'
      readonly name: string
      readonly publicKey: string
      readonly owner: boolean
      readonly tiers: readonly string[]
    }

export type AdminResult = {
  /** Entries flagged for rotation at their source. */
  readonly affected: readonly string[]
  /** Members `member.rm` removed: every name sharing the removed key. */
  readonly removed: readonly string[]
  readonly ownerRotated: boolean
}

export async function runAdminOp(vault: Vault, request: AdminOp): Promise<AdminResult> {
  const admin = new Admin(vault)
  const before = Object.keys(vault.state.members)
  const owner = vault.state.owner.signPublic
  const affected = await dispatch(admin, request)
  return {
    affected,
    removed: before.filter((name) => vault.state.members[name] === undefined),
    ownerRotated: vault.state.owner.signPublic !== owner,
  }
}

async function dispatch(admin: Admin, request: AdminOp): Promise<readonly string[]> {
  switch (request.op) {
    case 'tier.add':
      await admin.addTier(request.name)
      return []
    case 'tier.rm':
      await admin.removeTier(request.name)
      return []
    case 'tier.include':
      await admin.include(request.tier, request.included)
      return []
    case 'tier.exclude':
      return admin.exclude(request.tier, request.included)
    case 'key.rotate':
      return admin.rotate(request.name)
    case 'ceiling.set':
      await admin.setCeiling(request.name, request.tier)
      return []
    case 'ceiling.rm':
      await admin.removeCeiling(request.name)
      return []
    case 'signer.add':
      await admin.setSigner(request.id, request.publicKey, request.tiers)
      return []
    case 'signer.rm':
      await admin.removeSigner(request.name)
      return []
    case 'member.add': {
      const pub = decodeMemberPublic(request.publicKey)
      await admin.addMember(request.name, { ...pub, owner: request.owner, tiers: request.tiers })
      return []
    }
    case 'member.rm':
      return admin.removeMember(request.name)
  }
}
