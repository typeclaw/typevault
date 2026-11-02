import { encodeSecretKey, generateSecretKey, publicKeyOf, seal, type SecretKey } from './crypto'
import { utf8 } from './encoding'
import { sealEntry, type SignerRef, signerOf } from './entries'
import { TypeVaultError } from './errors'
import { wrapPath } from './keyring'
import { type Group, groupsDoc, includersOf, reach, type VaultState } from './state'
import type { Txn } from './txn'
import type { Vault } from './vault'

export type RotateContext = {
  readonly vault: Vault
  readonly operator: SecretKey
  readonly state: VaultState
  readonly txn: Txn
}

const signedBy = (signer: SignerRef, group: string): boolean =>
  (signer.kind === 'group' && signer.group === group) ||
  (signer.kind === 'cert' && signer.cert.issuer.kind === 'group' && signer.cert.issuer.group === group)

/**
 * Stages a new key generation for `name` into `txn`: fresh wraps for the operator and every includer,
 * re-wraps of the groups it includes, re-sealed entries, and finally the generation flip in groups.json.
 * Entries the old key could reach are flagged `needsRotation`; their names are returned.
 */
export async function rotateGroup(context: RotateContext, name: string): Promise<readonly string[]> {
  const { vault, operator, state, txn } = context
  const meta = state.groups[name]
  if (meta === undefined) throw new TypeVaultError('not_found', `no group "${name}"`)
  const gen = meta.gen + 1
  const key = await generateSecretKey({ kind: 'group', group: name, gen })
  const updated: Group = { ...meta, gen, ...(await publicKeyOf(key)) }
  const next: VaultState = { ...state, groups: { ...state.groups, [name]: updated } }
  const encoded = utf8(encodeSecretKey(key))

  txn.put(wrapPath(name, gen, { kind: 'operator' }), await seal([state.operator.recipient], encoded))
  for (const includer of includersOf(state.groups, name)) {
    const holder = state.groups[includer]
    if (holder === undefined) continue
    txn.put(
      wrapPath(name, gen, { kind: 'group', group: includer, gen: holder.gen }),
      await seal([holder.recipient], encoded),
    )
  }
  for (const included of meta.includes) {
    const includedKey = await vault.keyring.unlock(included)
    const includedGen = state.groups[included]?.gen
    if (includedKey === undefined || includedGen === undefined) continue
    const sealed = await seal([updated.recipient], utf8(encodeSecretKey(includedKey)))
    txn.put(wrapPath(included, includedGen, { kind: 'group', group: name, gen }), sealed)
    txn.remove(wrapPath(included, includedGen, { kind: 'group', group: name, gen: meta.gen }))
  }
  txn.remove(`groups/${name}/${meta.gen}`)

  const reached = reach(state.groups, name)
  const affected: string[] = []
  const now = new Date().toISOString()
  const { entries } = await vault.scan()
  for (const { envelope, payload } of entries) {
    const exposed = reached.has(envelope.group)
    if (!exposed && !signedBy(envelope.signer, name)) continue
    if (exposed) affected.push(payload.name)
    const draft = { id: envelope.id, group: envelope.group, rev: envelope.rev + 1, at: now }
    const resealed = await sealEntry(
      { ...draft, payload: exposed ? { ...payload, needsRotation: true } : payload },
      next,
      signerOf(operator),
    )
    txn.put(`entries/${envelope.id}.json`, `${JSON.stringify(resealed, null, 2)}\n`)
  }
  txn.put('groups.json', groupsDoc(next.groups, operator, state.seqs.groups + 1))
  return affected.sort()
}
