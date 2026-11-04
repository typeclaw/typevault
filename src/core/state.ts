import { existsSync, readFileSync } from 'node:fs'

import { z } from 'zod'

import { type PublicKey, type SecretKey, sign, verifySignature } from './crypto'
import { canonicalJson, fromUtf8, type Json, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { atomicWrite } from './fsx'
import type { Layout } from './layout'
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

const PublicKeySchema = z.object({ recipient: z.string().startsWith('age1'), signPublic: z.string() })
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
const TrustSchema = z.object({ ownerSignPublic: z.string() })

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
  const doc = z.object({ body: z.json(), sig: z.string() }).parse(JSON.parse(fromUtf8(readFileSync(path))))
  if (!verifySignature(owner.signPublic, utf8(canonicalJson(doc.body)), doc.sig)) {
    throw new TypeVaultError('tampered', `${path} is not signed by the vault owner`)
  }
  return schema.parse(doc.body)
}

/** The owner key is trusted on first use (or pinned via TYPEVAULT_OWNER); a changed key is tampering. */
function checkTrust(layout: Layout, owner: PublicKey, env: Readonly<Record<string, string | undefined>>): void {
  const pinned = env['TYPEVAULT_OWNER']
  if (pinned !== undefined && pinned !== '') {
    if (pinned !== owner.signPublic) throw new TypeVaultError('tampered', 'vault owner does not match TYPEVAULT_OWNER')
    return
  }
  if (!existsSync(layout.trustFile)) {
    atomicWrite(layout.trustFile, JSON.stringify({ ownerSignPublic: owner.signPublic }), 0o600)
    return
  }
  const trust = TrustSchema.parse(JSON.parse(fromUtf8(readFileSync(layout.trustFile))))
  if (trust.ownerSignPublic !== owner.signPublic) {
    throw new TypeVaultError('tampered', 'vault owner key changed since this machine first trusted it')
  }
}

export function loadState(layout: Layout, env: Readonly<Record<string, string | undefined>> = process.env): VaultState {
  if (!existsSync(layout.ownerFile))
    throw new TypeVaultError('not_found', `no vault at ${layout.vault} (run typevault init)`)
  const owner = PublicKeySchema.parse(JSON.parse(fromUtf8(readFileSync(layout.ownerFile))))
  checkTrust(layout, owner, env)
  const tiers = readSigned(layout.tiersFile, TiersBody, owner)
  const members = readSigned(layout.membersFile, MembersBody, owner)
  const signers = readSigned(layout.signersFile, SignersBody, owner)
  const ceilings = readSigned(layout.ceilingsFile, CeilingsBody, owner)
  // An older, still validly signed manifest from git history would resurrect removed signers or ceilings.
  const marks = new RevisionMarks(layout.revisionsFile)
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
  marks.save()
  return {
    owner,
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
