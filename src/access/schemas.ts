import { z } from 'zod'

import { type EntryType, isEntryType, parseEntryName } from '../core/naming'
import type { EntrySummary, EntryValue } from './types'

const SummaryShape = {
  name: z.string().transform((name) => parseEntryName(name)),
  type: z.string().refine(isEntryType),
  group: z.string(),
  rev: z.number().int(),
  tags: z.array(z.string()),
  rotated: z.string(),
  needsRotation: z.boolean(),
}

export const EntrySummarySchema = z.object(SummaryShape)
export const EntryValueSchema = z.object({
  ...SummaryShape,
  id: z.string(),
  created: z.string(),
  fields: z.record(z.string(), z.string()),
  env: z.string().optional(),
  origin: z.string().optional(),
})

const entryType = (type: string): EntryType => {
  if (isEntryType(type)) return type
  throw new TypeError(`unknown entry type ${type}`)
}

export function toSummaryValue(parsed: z.infer<typeof EntrySummarySchema>): EntrySummary {
  return { ...parsed, type: entryType(parsed.type) }
}

export function toEntryValue(parsed: z.infer<typeof EntryValueSchema>): EntryValue {
  const { env, origin, type, ...rest } = parsed
  return {
    ...rest,
    type: entryType(type),
    ...(env === undefined ? {} : { env }),
    ...(origin === undefined ? {} : { origin }),
  }
}
