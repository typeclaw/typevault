import { z } from 'zod'

import { isPreset, parseEntryName } from '../core/naming'
import { FieldsSchema } from '../core/payload'

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
