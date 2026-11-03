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
  readonly state: VaultState
  readonly txn: Txn
}

const signedBy = (signer: SignerRef, tier: string): boolean =>
  (signer.kind === 'tier' && signer.tier === tier) ||
  (signer.kind === 'cert' && signer.cert.issuer.kind === 'tier' && signer.cert.issuer.tier === tier)

/**
 * Stages a new key generation for `name` into `txn`: fresh wraps for the owner and every includer,
 * re-wraps of the tiers it includes, re-sealed entries, and finally the generation flip in tiers.json.
 * Entries the old key could reach are flagged `needsRotation`; their names are returned.
 */
export async function rotateTier(context: RotateContext, name: string): Promise<readonly string[]> {
  const { vault, owner, state, txn } = context
  const meta = state.tiers[name]
  if (meta === undefined) throw new TypeVaultError('not_found', `no tier "${name}"`)
  const gen = meta.gen + 1
  const key = await generateSecretKey({ kind: 'tier', tier: name, gen })
  const updated: Tier = { ...meta, gen, ...(await publicKeyOf(key)) }
  const next: VaultState = { ...state, tiers: { ...state.tiers, [name]: updated } }
  const encoded = utf8(encodeSecretKey(key))

  txn.put(wrapPath(name, gen, { kind: 'owner' }), await seal([state.owner.recipient], encoded))
  for (const includer of includersOf(state.tiers, name)) {
    const holder = state.tiers[includer]
    if (holder === undefined) continue
    txn.put(
      wrapPath(name, gen, { kind: 'tier', tier: includer, gen: holder.gen }),
      await seal([holder.recipient], encoded),
    )
  }
  for (const included of meta.includes) {
    const includedKey = await vault.keyring.unlock(included)
    const includedGen = state.tiers[included]?.gen
    if (includedKey === undefined || includedGen === undefined) continue
    const sealed = await seal([updated.recipient], utf8(encodeSecretKey(includedKey)))
    txn.put(wrapPath(included, includedGen, { kind: 'tier', tier: name, gen }), sealed)
    txn.remove(wrapPath(included, includedGen, { kind: 'tier', tier: name, gen: meta.gen }))
  }
  txn.remove(`tiers/${name}/${meta.gen}`)

  const reached = reach(state.tiers, name)
  const affected: string[] = []
  const now = new Date().toISOString()
  const { entries } = await vault.scan()
  for (const { envelope, payload } of entries) {
    const exposed = reached.has(envelope.tier)
    if (!exposed && !signedBy(envelope.signer, name)) continue
    if (exposed) affected.push(payload.name)
    const draft = { id: envelope.id, tier: envelope.tier, rev: envelope.rev + 1, at: now }
    const resealed = await sealEntry(
      { ...draft, payload: exposed ? { ...payload, needsRotation: true } : payload },
      next,
      signerOf(owner),
    )
    txn.put(`entries/${envelope.id}.json`, `${JSON.stringify(resealed, null, 2)}\n`)
  }
  txn.put('tiers.json', tiersDoc(next.tiers, owner, state.seqs.tiers + 1))
  return affected.sort()
}
