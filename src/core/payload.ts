import { z } from 'zod'

import { fromUtf8, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { type EntryName, type Field, isFieldName, isUsableEnvName, parseEntryName } from './naming'
import { decodeBase64Url, isPasskeyPrivateKey, isUserHandle, MAX_SIGN_COUNT } from './passkey'

/** The plaintext sealed inside an entry file: everything except the tier is secret. */
export type EntryPayload = {
  readonly v: 1
  readonly name: EntryName
  readonly fields: Readonly<Record<string, Field>>
  readonly env?: string
  readonly origin?: string
  /** The password-manager item an import took this entry from, so a later import finds it after a rename. */
  readonly source?: string
  readonly tags: readonly string[]
  readonly created: string
  readonly rotated: string
  readonly needsRotation?: boolean
}

const Base64UrlSchema = z
  .string()
  .refine((text) => decodeBase64Url(text) !== undefined, 'expected canonical base64url without padding')

export const FieldSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('secret'), value: z.string() }).strict(),
  z.object({ type: z.literal('text'), value: z.string() }).strict(),
  z.object({ type: z.literal('totp'), value: z.string() }).strict(),
  z
    .object({
      type: z.literal('oauth'),
      value: z
        .record(z.string(), z.string())
        .refine((value) => typeof value['access_token'] === 'string', 'OAuth requires access_token'),
    })
    .strict(),
  z
    .object({
      type: z.literal('passkey'),
      value: z
        .object({
          rp_id: z.string().min(1),
          credential_id: Base64UrlSchema,
          private_key: z.string().refine((key) => {
            const bytes = decodeBase64Url(key)
            return bytes !== undefined && isPasskeyPrivateKey(bytes)
          }, 'expected a PKCS#8 P-256, Ed25519 or RSA private key in base64url'),
          discoverable: z.boolean(),
          user_handle: z
            .string()
            .refine(isUserHandle, 'expected a user handle of at most 64 bytes in canonical base64url')
            .exactOptional(),
          user_name: z.string().exactOptional(),
          sign_count: z.number().int().nonnegative().max(MAX_SIGN_COUNT).exactOptional(),
        })
        .strict()
        .refine(
          (value) => !value.discoverable || value.user_handle !== undefined,
          'a discoverable passkey needs its user_handle',
        ),
    })
    .strict(),
])
export const FieldsSchema = z.record(z.string().refine(isFieldName), FieldSchema)

const PayloadSchema = z
  .object({
    v: z.literal(1),
    name: z.string(),
    fields: FieldsSchema,
    env: z
      .string()
      .regex(/^[A-Z_][A-Z0-9_]*$/)
      .optional(),
    origin: z.string().optional(),
    source: z.string().optional(),
    tags: z.array(z.string()),
    created: z.iso.datetime(),
    rotated: z.iso.datetime(),
    needsRotation: z.boolean().optional(),
  })
  .strict()

function parsePayload(value: unknown, code: 'invalid' | 'tampered'): z.infer<typeof PayloadSchema> {
  const parsed = PayloadSchema.safeParse(value)
  if (!parsed.success)
    throw new TypeVaultError(code, `malformed entry payload: ${parsed.error.issues[0]?.message ?? 'invalid'}`)
  return parsed.data
}

export function encodePayload(payload: EntryPayload): Uint8Array {
  parsePayload(payload, 'invalid')
  const { env } = payload
  if (env !== undefined && !isUsableEnvName(env)) throw new TypeVaultError('invalid', `${env} is not a usable env name`)
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
  const { name, env, origin, source, needsRotation, ...rest } = parsePayload(value, 'tampered')
  return {
    ...rest,
    name: parseEntryName(name),
    ...(env === undefined ? {} : { env }),
    ...(origin === undefined ? {} : { origin }),
    ...(source === undefined ? {} : { source }),
    ...(needsRotation === undefined ? {} : { needsRotation }),
  }
}
