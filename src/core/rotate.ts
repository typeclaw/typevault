import { encodeSecretKey, generateSecretKey, publicKeyOf, seal, type SecretKey } from './crypto'
import { utf8 } from './encoding'
import { sealEntry, type SignerRef, signerOf } from './entries'
import { TypeVaultError } from './errors'
import { wrapPath } from './keyring'
import { type Tier, tiersDoc, includersOf, reach, type VaultState } from './state'
import type { Txn } from './txn'
import type { Vault } from './vault'

export type RotateContext = {
  readonly vault: Vault
  readonly owner: SecretKey
  /** The state the rotation is for: its members are who gets the new keys. */
  readonly state: VaultState
  readonly txn: Txn
  /** Whether the old keys may have leaked, so every secret they reached must be rotated at its source. */
  readonly exposed: boolean
}

const signedBy = (signer: SignerRef, tier: string): boolean =>
  (signer.kind === 'tier' && signer.tier === tier) ||
  (signer.kind === 'cert' && signer.cert.issuer.kind === 'tier' && signer.cert.issuer.tier === tier)

/**
 * Stages a new key generation for each of `names` into `txn`, all in one transaction: fresh wraps for the owner,
 * every includer and every member holding the tier, re-wraps of the tiers each one includes, re-sealed entries, and
 * finally the generation flip in tiers.json. When `exposed`, entries the old keys could reach are flagged
 * `needsRotation` and their names returned.
 */
export async function rotateTiers(context: RotateContext, names: readonly string[]): Promise<readonly string[]> {
  const { vault, owner, state, txn, exposed } = context
  if (names.length === 0) return []
  const rotated = new Map<string, { readonly key: SecretKey; readonly tier: Tier }>()
  for (const name of new Set(names)) {
    const meta = state.tiers[name]
    if (meta === undefined) throw new TypeVaultError('not_found', `no tier "${name}"`)
    const key = await generateSecretKey({ kind: 'tier', tier: name, gen: meta.gen + 1 })
    rotated.set(name, { key, tier: { ...meta, gen: meta.gen + 1, ...(await publicKeyOf(key)) } })
  }
  const tiers = { ...state.tiers, ...Object.fromEntries([...rotated].map(([name, { tier }]) => [name, tier])) }
  const next: VaultState = { ...state, tiers }

  for (const [name, { key, tier }] of rotated) {
    const oldGen = state.tiers[name]?.gen ?? 0
    const encoded = utf8(encodeSecretKey(key))
    txn.put(wrapPath(name, tier.gen, { kind: 'owner' }), await seal([state.owner.recipient], encoded))
    for (const includer of includersOf(tiers, name)) {
      const holder = tiers[includer]
      if (holder === undefined) continue
      txn.put(
        wrapPath(name, tier.gen, { kind: 'tier', tier: includer, gen: holder.gen }),
        await seal([holder.recipient], encoded),
      )
    }
    for (const [member, holder] of Object.entries(state.members)) {
      if (!holder.tiers.includes(name)) continue
      txn.put(wrapPath(name, tier.gen, { kind: 'member', name: member }), await seal([holder.recipient], encoded))
    }
    // An included tier rotated here already wrapped its new key to this tier's new key above.
    for (const included of tier.includes.filter((other) => !rotated.has(other))) {
      const includedKey = await vault.keyring.unlock(included)
      const includedGen = state.tiers[included]?.gen
      if (includedKey === undefined || includedGen === undefined) continue
      const sealed = await seal([tier.recipient], utf8(encodeSecretKey(includedKey)))
      txn.put(wrapPath(included, includedGen, { kind: 'tier', tier: name, gen: tier.gen }), sealed)
      txn.remove(wrapPath(included, includedGen, { kind: 'tier', tier: name, gen: oldGen }))
    }
    txn.remove(`tiers/${name}/${oldGen}`)
  }

  const reached = new Set([...rotated.keys()].flatMap((name) => [...reach(state.tiers, name)]))
  const affected: string[] = []
  const now = new Date().toISOString()
  const { entries } = await vault.scan()
  for (const { envelope, payload } of entries) {
    const reachable = reached.has(envelope.tier)
    if (!reachable && ![...rotated.keys()].some((name) => signedBy(envelope.signer, name))) continue
    const flagged = exposed && reachable
    if (flagged) affected.push(payload.name)
    const draft = { id: envelope.id, tier: envelope.tier, rev: envelope.rev + 1, at: now }
    const resealed = await sealEntry(
      { ...draft, payload: flagged ? { ...payload, needsRotation: true } : payload },
      next,
      signerOf(owner),
    )
    txn.put(`entries/${envelope.id}.json`, `${JSON.stringify(resealed, null, 2)}\n`)
  }
  txn.put('tiers.json', tiersDoc(tiers, owner, state.seqs.tiers + 1))
  return affected.sort()
}
