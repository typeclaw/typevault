import type { PublicKey, SecretKey } from './crypto'
import { sign } from './crypto'
import { canonicalJson, type Json, utf8 } from './encoding'
import { TypeVaultError } from './errors'

export type Tier = {
  readonly includes: readonly string[]
  readonly gen: number
  readonly recipient: string
  readonly signPublic: string
}
export type Signer = { readonly signPublic: string; readonly tiers: readonly string[] }
export type Tiers = Readonly<Record<string, Tier>>

/** A person (unlocks with a password) or a machine (holds its key directly). */
export type MemberKind = 'human' | 'machine'
export type Member = {
  readonly kind: MemberKind
  readonly recipient: string
  readonly signPublic: string
  /** Owners get the owner key wrapped to them. */
  readonly owner: boolean
  /** Tiers whose key is wrapped to this member. */
  readonly tiers: readonly string[]
}
export type Members = Readonly<Record<string, Member>>

/** Everything public about a vault. Tiers, members, signers and ceilings are signed by the owner key. */
export type ManifestSeqs = {
  readonly tiers: number
  readonly members: number
  readonly signers: number
  readonly ceilings: number
}

export type VaultState = {
  readonly owner: PublicKey
  /** The vault's first owner key, its audit identity: signed by the current owner and pinned on this machine. */
  readonly origin: string
  /** The verified handover chain that led to `owner`. */
  readonly handovers: { from: string; to: { recipient: string; signPublic: string }; sig: string }[]
  /** Each manifest's sequence number: every signed change bumps it, and a lower one is a rollback. */
  readonly seqs: ManifestSeqs
  readonly tiers: Tiers
  readonly members: Members
  readonly signers: Readonly<Record<string, Signer>>
  readonly ceilings: Readonly<Record<string, string>>
}

const TIER_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
export function parseTierName(name: string): string {
  if (!TIER_NAME.test(name)) throw new TypeVaultError('invalid', `invalid tier name "${name}" (use [a-z0-9-])`)
  return name
}

export function parseMemberName(name: string): string {
  if (!TIER_NAME.test(name)) throw new TypeVaultError('invalid', `invalid member name "${name}" (use [a-z0-9-])`)
  return name
}

export const signedDoc = (body: Json, key: SecretKey): string =>
  `${JSON.stringify({ body, sig: sign(key.signSecret, utf8(canonicalJson(body))) }, null, 2)}\n`

export const tiersDoc = (tiers: Tiers, key: SecretKey, seq: number): string => signedDoc({ v: 1, seq, tiers }, key)
export const membersDoc = (members: Members, key: SecretKey, seq: number): string =>
  signedDoc({ v: 1, seq, members }, key)
export const signersDoc = (signers: VaultState['signers'], key: SecretKey, seq: number): string =>
  signedDoc({ v: 1, seq, signers }, key)
export const ceilingsDoc = (ceilings: VaultState['ceilings'], key: SecretKey, seq: number): string =>
  signedDoc({ v: 1, seq, ceilings }, key)

/** Every tier `name` reaches through includes, itself included. */
export function reach(tiers: Tiers, name: string): ReadonlySet<string> {
  const seen = new Set<string>()
  const visit = (tier: string): void => {
    if (seen.has(tier)) return
    seen.add(tier)
    for (const included of tiers[tier]?.includes ?? []) visit(included)
  }
  visit(name)
  return seen
}

export const reachesTier = (tiers: Tiers, from: readonly string[], target: string): boolean =>
  from.some((tier) => tier === '*' || reach(tiers, tier).has(target))

export const includersOf = (tiers: Tiers, name: string): readonly string[] =>
  Object.entries(tiers)
    .filter(([, tier]) => tier.includes.includes(name))
    .map(([includer]) => includer)
