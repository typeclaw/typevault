import { hmac } from '@noble/hashes/hmac.js'
import { sha1 } from '@noble/hashes/legacy.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { base32 } from '@scure/base'
import { z } from 'zod'

import { TypeVaultError } from '../core/errors'

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512'
export type TotpParams = {
  readonly secret: Uint8Array
  readonly digits: 6 | 7 | 8
  readonly period: number
  readonly algorithm: TotpAlgorithm
}

const SeedOptions = z.object({
  digits: z.enum(['6', '7', '8']).transform((value) => (value === '6' ? 6 : value === '7' ? 7 : 8)),
  period: z
    .string()
    .regex(/^[1-9]\d*$/)
    .transform(Number)
    .refine(Number.isSafeInteger),
  algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']),
})

const hashes = { SHA1: sha1, SHA256: sha256, SHA512: sha512 } as const

export function parseTotpSeed(input: string): TotpParams {
  try {
    const text = input.trim()
    const uri = /^otpauth:/i.test(text) ? new URL(text) : undefined
    if (uri && (uri.hostname !== 'totp' || uri.pathname.length <= 1 || uri.username || uri.password || uri.port)) {
      throw new TypeVaultError('invalid', 'invalid TOTP URI')
    }
    const query = uri?.searchParams
    const options = SeedOptions.safeParse({
      digits: query?.get('digits') ?? '6',
      period: query?.get('period') ?? '30',
      algorithm: query?.get('algorithm')?.toUpperCase() ?? 'SHA1',
    })
    if (!options.success) throw new TypeVaultError('invalid', 'invalid TOTP parameters')
    const encoded = (uri ? (query?.get('secret') ?? '') : text).replace(/\s/g, '').toUpperCase()
    if (!encoded) throw new TypeVaultError('invalid', 'missing TOTP secret')
    const secret = base32.decode(encoded.padEnd(Math.ceil(encoded.length / 8) * 8, '='))
    return { secret, ...options.data }
  } catch (error) {
    if (error instanceof Error) throw new TypeVaultError('invalid', 'invalid TOTP seed')
    throw error
  }
}

function timeSeconds(params: TotpParams, at: Date): number {
  const seconds = at.getTime() / 1000
  if (!Number.isFinite(seconds) || seconds < 0 || !Number.isSafeInteger(params.period) || params.period <= 0) {
    throw new TypeVaultError('invalid', 'invalid TOTP time or period')
  }
  return seconds
}

export function totpCode(params: TotpParams, at: Date): string {
  const counter = BigInt(Math.floor(timeSeconds(params, at) / params.period))
  const message = new Uint8Array(8)
  new DataView(message.buffer).setBigUint64(0, counter)
  const digest = hmac(hashes[params.algorithm], params.secret, message)
  const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength)
  const offset = view.getUint8(digest.length - 1) & 0x0f
  const truncated = view.getUint32(offset) & 0x7fffffff
  return (truncated % 10 ** params.digits).toString().padStart(params.digits, '0')
}

export function totpRemainingSeconds(params: TotpParams, at: Date): number {
  return Math.ceil(params.period - (timeSeconds(params, at) % params.period))
}
