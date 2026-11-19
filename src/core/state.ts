import { existsSync } from 'node:fs'

import { z } from 'zod'

import { type PublicKey, type SecretKey, sign, verifySignature } from './crypto'
import { canonicalJson, type Json, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { readJsonFile } from './json-file'
import type { Layout } from './layout'
import {
  firstOwnerSignPublic,
  type Owner,
  PublicKeySchema,
  readOwner as verifiedOwner,
  trustOwner,
} from './owner-trust'
import { RevisionMarks } from './revisions'

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
  /** The first owner key of the verified handover chain, as pinned on this machine. */
  readonly origin: string
  /** The verified handover chain that led to `owner`. */
  readonly handovers: Owner['handovers']
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

const TierSchema = PublicKeySchema.extend({ includes: z.array(z.string()), gen: z.number().int().positive() })
const seq = z.number().int().positive()
const TiersBody = z.object({ v: z.literal(1), seq, tiers: z.record(z.string(), TierSchema) })
const MembersBody = z.object({
  v: z.literal(1),
  seq,
  members: z.record(
    z.string(),
    PublicKeySchema.extend({
      kind: z.enum(['human', 'machine']),
      owner: z.boolean(),
      tiers: z.array(z.string()),
    }),
  ),
})
const SignersBody = z.object({
  v: z.literal(1),
  seq,
  signers: z.record(z.string(), z.object({ signPublic: z.string(), tiers: z.array(z.string()) })),
})
const CeilingsBody = z.object({ v: z.literal(1), seq, ceilings: z.record(z.string(), z.string()) })

export const signedDoc = (body: Json, key: SecretKey): string =>
  `${JSON.stringify({ body, sig: sign(key.signSecret, utf8(canonicalJson(body))) }, null, 2)}\n`

export const tiersDoc = (tiers: Tiers, key: SecretKey, seq: number): string => signedDoc({ v: 1, seq, tiers }, key)
export const membersDoc = (members: Members, key: SecretKey, seq: number): string =>
  signedDoc({ v: 1, seq, members }, key)
export const signersDoc = (signers: VaultState['signers'], key: SecretKey, seq: number): string =>
  signedDoc({ v: 1, seq, signers }, key)
export const ceilingsDoc = (ceilings: VaultState['ceilings'], key: SecretKey, seq: number): string =>
  signedDoc({ v: 1, seq, ceilings }, key)

function readSigned<T extends Json>(path: string, schema: z.ZodType<T>, owner: PublicKey): T {
  const doc = readJsonFile(path, z.object({ body: z.json(), sig: z.string() }))
  if (!verifySignature(owner.signPublic, utf8(canonicalJson(doc.body)), doc.sig)) {
    throw new TypeVaultError('tampered', `${path} is not signed by the vault owner`)
  }
  const parsed = schema.safeParse(doc.body)
  if (!parsed.success) throw new TypeVaultError('tampered', `${path} has a malformed manifest body`)
  return parsed.data
}

export function readOwner(layout: Layout): PublicKey {
  if (!existsSync(layout.ownerFile))
    throw new TypeVaultError('not_found', `no vault at ${layout.vault} (run typevault init)`)
  return readJsonFile(layout.ownerFile, PublicKeySchema)
}

export function loadState(layout: Layout, env: Readonly<Record<string, string | undefined>> = process.env): VaultState {
  const owner = verifiedOwner(layout)
  const tiers = readSigned(layout.tiersFile, TiersBody, owner)
  const members = readSigned(layout.membersFile, MembersBody, owner)
  const signers = readSigned(layout.signersFile, SignersBody, owner)
  const ceilings = readSigned(layout.ceilingsFile, CeilingsBody, owner)
  // An older, still validly signed manifest from git history would resurrect removed signers or ceilings.
  const marks = new RevisionMarks(layout.revisionsFile)
  if (!marks.accept('owner:handovers', owner.handovers.length)) {
    throw new TypeVaultError('tampered', 'owner.json has fewer handovers than this machine has seen')
  }
  // Anyone can sign a link from a key of their own, so the chain alone doesn't prove where it starts. The first origin
  // this machine trusted is pinned here; the audit chain is named after it.
  const claimed = firstOwnerSignPublic(owner)
  const origin = `owner:origin:${claimed}`
  if (!marks.allows('owner:origin', 0) && marks.allows(origin, 0)) {
    throw new TypeVaultError('tampered', 'owner.json claims a different first owner than this machine trusted')
  }
  marks.accept('owner:origin', 1)
  marks.accept(origin, 1)
  for (const [name, doc] of [
    ['tiers', tiers],
    ['members', members],
    ['signers', signers],
    ['ceilings', ceilings],
  ] as const) {
    if (!marks.accept(`manifest:${name}`, doc.seq)) {
      throw new TypeVaultError(
        'tampered',
        `${name}.json was rolled back to seq ${doc.seq} (this machine has seen newer)`,
      )
    }
  }
  trustOwner(layout, owner, env['TYPEVAULT_OWNER'])
  marks.save()
  return {
    owner,
    origin: claimed,
    handovers: owner.handovers,
    seqs: { tiers: tiers.seq, members: members.seq, signers: signers.seq, ceilings: ceilings.seq },
    tiers: tiers.tiers,
    members: members.members,
    signers: signers.signers,
    ceilings: ceilings.ceilings,
  }
}

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
