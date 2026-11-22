import { z } from 'zod'

import { isPreset, parseEntryName } from '../core/naming'
import { FieldsSchema } from '../core/payload'
import { OwnerChangeId } from './owner-changes'

const name = z.string().transform((value) => parseEntryName(value))
const preset = z.string().refine(isPreset, 'unknown preset').optional()
const reason = z.string().max(500).optional()
/** Every request under a grant matches against its `only` patterns, so a grant may not carry an unbounded list. */
const only = z.array(z.string().max(256)).max(100).default([])
/** Every request under a grant checks its tiers too, so they are capped like `only`. */
const tiers = z.array(z.string().max(256)).max(100)

export const NameBody = z.object({ name, reason, tier: z.string().optional() })
export const ValuesBody = z.object({ only, reason })
export const SetBody = z.object({
  name,
  fields: FieldsSchema,
  tier: z.string().optional(),
  env: z
    .string()
    .regex(/^[A-Z_][A-Z0-9_]*$/)
    .optional(),
  origin: z.string().optional(),
  tags: z.array(z.string()).optional(),
  ifRev: z.number().int().nonnegative().optional(),
})
/** The entries an import writes, sent as staged chunks of their serialized JSON. */
export const ImportEntries = z.array(
  SetBody.omit({ tier: true, ifRev: true }).extend({ source: z.string().optional() }),
)
/** One base64 chunk of an import, staged until `ImportBody` commits it; the first chunk starts a new upload. */
export const ImportStageBody = z.object({ upload: z.string().max(64).optional(), chunk: z.base64() })
export const ImportBody = z.object({ upload: z.string().max(64), tier: z.string() })
export const MoveBody = z.object({ from: name, to: name })
export const DeriveBody = z.object({
  tiers: tiers.optional(),
  only,
  ttl: z.string().optional(),
  label: z.string().max(200).optional(),
})
export const RequestBody = z.object({ name, preset, tier: z.string().optional(), reason: z.string().min(1).max(500) })
export const WaitBody = z.object({ id: z.string() })
export const AttachBody = z.object({ vault: z.string() })
export const GrantBody = z.object({
  tiers: tiers.min(1),
  only,
  ttl: z.string().default('1h'),
  label: z.string().max(200).default('unlabeled'),
  sealed: z.boolean().default(false),
})
export const RevokeBody = z.object({ id: z.string().optional(), label: z.string().optional() })
export const AuditBody = z.object({ label: z.string().optional() })
const named = z.object({
  op: z.enum(['tier.add', 'tier.rm', 'key.rotate', 'ceiling.rm', 'signer.rm', 'member.rm']),
  name: z.string(),
})
export const AdminBody = z.object({
  request: z.union([
    named,
    z.object({ op: z.enum(['tier.include', 'tier.exclude']), tier: z.string(), included: z.string() }),
    z.object({ op: z.literal('ceiling.set'), name: z.string(), tier: z.string() }),
    z.object({ op: z.literal('signer.add'), id: z.string(), publicKey: z.string(), tiers }),
    z.object({ op: z.literal('member.add'), name: z.string(), publicKey: z.string(), owner: z.boolean(), tiers }),
  ]),
  proof: z.object({ nonce: z.string().max(64), signature: z.string().max(200) }).optional(),
  /** The caller's own id for this change: admitting it again changes nothing. */
  change: OwnerChangeId,
})
export const AdminResultSchema = z.object({
  affected: z.array(z.string()),
  removed: z.array(z.string()),
  ownerRotated: z.boolean(),
  /** Ceilings the change set whose admin sockets the session couldn't open. */
  unserved: z.array(z.string()),
  /** False when the change committed but the session's grant couldn't be widened to the tiers it now reaches. */
  scopeRefreshed: z.boolean(),
})
export const ChallengeSchema = z.object({ open: z.boolean(), nonce: z.string() })
export const AdmittedSchema = z.object({ change: OwnerChangeId })
export const AdminWaitBody = z.object({
  change: OwnerChangeId,
  waitMs: z.number().int().min(0).max(5_000).optional(),
})
export const AdminWaitedSchema = z.union([
  z.object({ done: z.literal(false) }),
  z.object({ done: z.literal(true), result: AdminResultSchema }),
])
