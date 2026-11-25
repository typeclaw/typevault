import { existsSync } from 'node:fs'

import { z } from 'zod'

import { type PublicKey, verifySignature } from './crypto'
import { canonicalJson, type Json, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { readJsonFile } from './json-file'
import type { Layout } from './layout'
import type { VaultState } from './model'
import { auditChainOf, PublicKeySchema, readOwner as verifiedOwner, trustOwner } from './owner-trust'
import { RevisionMarks } from './revisions'

export * from './model'

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
  // The current owner signs the audit chain, so trusting that owner authenticates it. A machine also pins the first
  // chain it trusted, so no later owner.json can move its audit anchors elsewhere.
  const auditChain = auditChainOf(owner)
  const pinned = `owner:audit:${auditChain}`
  if (!marks.allows('owner:audit', 0) && marks.allows(pinned, 0)) {
    throw new TypeVaultError('tampered', 'owner.json names a different audit chain than this machine trusted')
  }
  marks.accept('owner:audit', 1)
  marks.accept(pinned, 1)
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
    origin: auditChain,
    handovers: owner.handovers,
    seqs: { tiers: tiers.seq, members: members.seq, signers: signers.seq, ceilings: ceilings.seq },
    tiers: tiers.tiers,
    members: members.members,
    signers: signers.signers,
    ceilings: ceilings.ceilings,
  }
}
