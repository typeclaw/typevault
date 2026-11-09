import { z } from 'zod'

import { parseEntryName } from '../core/naming'
import { FieldsSchema } from '../core/payload'
import type { EntrySummary, EntryValue } from './types'

const SummaryShape = {
  name: z.string().transform((name) => parseEntryName(name)),
  tier: z.string(),
  rev: z.number().int(),
  tags: z.array(z.string()),
  rotated: z.string(),
  needsRotation: z.boolean(),
}

export const EntrySummarySchema = z.object({ ...SummaryShape, fieldNames: z.array(z.string()) })
export const EntryValueSchema = z.object({
  ...SummaryShape,
  id: z.string(),
  created: z.string(),
  fields: FieldsSchema,
  env: z.string().optional(),
  origin: z.string().optional(),
  source: z.string().optional(),
  trustedWriter: z.boolean().optional(),
})

export function toSummaryValue(parsed: z.infer<typeof EntrySummarySchema>): EntrySummary {
  return parsed
}

export function toEntryValue(parsed: z.infer<typeof EntryValueSchema>): EntryValue {
  const { env, origin, source, trustedWriter, ...rest } = parsed
  return {
    ...rest,
    ...(env === undefined ? {} : { env }),
    ...(origin === undefined ? {} : { origin }),
    ...(source === undefined ? {} : { source }),
    ...(trustedWriter === undefined ? {} : { trustedWriter }),
  }
}
