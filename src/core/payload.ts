import { z } from 'zod'

import { fromUtf8, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { type EntryName, type EntryType, isEntryType, parseEntryName } from './naming'

/** The plaintext sealed inside an entry file: everything except the group is secret. */
export type EntryPayload = {
  readonly v: 1
  readonly name: EntryName
  readonly type: EntryType
  readonly fields: Readonly<Record<string, string>>
  readonly env?: string
  readonly origin?: string
  readonly tags: readonly string[]
  readonly created: string
  readonly rotated: string
  readonly needsRotation?: boolean
}

const PayloadSchema = z.object({
  v: z.literal(1),
  name: z.string(),
  type: z.string().refine(isEntryType),
  fields: z.record(z.string(), z.string()),
  env: z
    .string()
    .regex(/^[A-Z_][A-Z0-9_]*$/)
    .optional(),
  origin: z.string().optional(),
  tags: z.array(z.string()),
  created: z.iso.datetime(),
  rotated: z.iso.datetime(),
  needsRotation: z.boolean().optional(),
})

export const encodePayload = (payload: EntryPayload): Uint8Array => utf8(JSON.stringify(payload))

export function decodePayload(bytes: Uint8Array): EntryPayload {
  const parsed = PayloadSchema.safeParse(JSON.parse(fromUtf8(bytes)))
  if (!parsed.success) throw new TypeVaultError('tampered', `malformed entry payload: ${parsed.error.message}`)
  const { name, type, env, origin, needsRotation, ...rest } = parsed.data
  if (!isEntryType(type)) throw new TypeVaultError('tampered', `unknown entry type "${type}"`)
  return {
    ...rest,
    name: parseEntryName(name),
    type,
    ...(env === undefined ? {} : { env }),
    ...(origin === undefined ? {} : { origin }),
    ...(needsRotation === undefined ? {} : { needsRotation }),
  }
}
