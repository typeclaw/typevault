import { z } from 'zod'

import { fromUtf8, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { type EntryName, type EntryType, isEntryType, isFieldName, isUsableEnvName, parseEntryName } from './naming'

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

/** Why a payload can't be stored, or undefined when it can. */
function payloadProblem(value: unknown): string | undefined {
  const parsed = PayloadSchema.safeParse(value)
  if (!parsed.success) return parsed.error.issues[0]?.message ?? 'malformed'
  const { type, fields, env } = parsed.data
  if (!isEntryType(type)) return `unknown type "${type}"`
  const invalid = Object.keys(fields).find((field) => !isFieldName(field))
  if (invalid !== undefined) return `invalid field name "${invalid}"`
  if (env !== undefined && !isUsableEnvName(env)) return `${env} is not a usable env name`
  return undefined
}

export function encodePayload(payload: EntryPayload): Uint8Array {
  const problem = payloadProblem(payload)
  if (problem !== undefined) throw new TypeVaultError('invalid', problem)
  return utf8(JSON.stringify(payload))
}

export function decodePayload(bytes: Uint8Array): EntryPayload {
  let value: unknown
  try {
    value = JSON.parse(fromUtf8(bytes))
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof TypeError)
      throw new TypeVaultError('tampered', 'entry payload is not JSON')
    throw error
  }
  const problem = payloadProblem(value)
  const parsed = PayloadSchema.safeParse(value)
  if (problem !== undefined || !parsed.success)
    throw new TypeVaultError('tampered', `malformed entry payload: ${problem ?? 'invalid'}`)
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
