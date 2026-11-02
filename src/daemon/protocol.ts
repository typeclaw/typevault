import { z } from 'zod'

import { isEntryType, parseEntryName } from '../core/naming'

const name = z.string().transform((value) => parseEntryName(value))
const type = z.string().refine(isEntryType, 'unknown entry type')
const reason = z.string().max(500).optional()

export const NameBody = z.object({ name, reason })
export const ValuesBody = z.object({ only: z.array(z.string()).default([]), reason })
export const SetBody = z.object({
  name,
  type,
  fields: z.record(z.string(), z.string()),
  group: z.string().optional(),
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
  groups: z.array(z.string()).optional(),
  only: z.array(z.string()).default([]),
  ttl: z.string().optional(),
  label: z.string().max(200).optional(),
})
export const RequestBody = z.object({ name, type, group: z.string().optional(), reason: z.string().min(1).max(500) })
export const WaitBody = z.object({ id: z.string() })
export const GrantBody = z.object({
  groups: z.array(z.string()).min(1),
  only: z.array(z.string()).default([]),
  ttl: z.string().default('1h'),
  label: z.string().max(200).default('unlabeled'),
  sealed: z.boolean().default(false),
})
export const RevokeBody = z.object({ id: z.string().optional(), label: z.string().optional() })
export const AuditBody = z.object({ label: z.string().optional() })
