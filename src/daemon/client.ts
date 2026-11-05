import { z } from 'zod'

import { type ErrorCode, TypeVaultError } from '../core/errors'

const ErrorSchema = z.object({ error: z.object({ code: z.string(), message: z.string() }) })
const CODES: readonly ErrorCode[] = [
  'invalid',
  'not_found',
  'denied',
  'conflict',
  'tampered',
  'expired',
  'locked',
  'unavailable',
  'in_use',
  'no_vault',
  'not_member',
]
const toCode = (code: string): ErrorCode => CODES.find((known) => known === code) ?? 'unavailable'

export type CallOptions = { readonly token?: string; readonly timeoutMs?: number }

/** One JSON request to the daemon over its unix socket. Daemon errors come back as TypeVaultError. */
export async function callDaemon<T>(
  socket: string,
  path: string,
  body: unknown,
  schema: z.ZodType<T>,
  options: CallOptions = {},
): Promise<T> {
  let response: Response
  try {
    response = await fetch(`http://typevault${path}`, {
      unix: socket,
      method: 'POST',
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/json',
        ...(options.token === undefined ? {} : { authorization: `Bearer ${options.token}` }),
      },
      signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
    })
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === 'TimeoutError') {
        throw new TypeVaultError('unavailable', 'the typevault daemon request timed out', { cause: error })
      }
      throw new TypeVaultError('unavailable', `the typevault daemon is not reachable at ${socket}`)
    }
    throw error
  }
  const payload: unknown = await response.json()
  if (!response.ok) {
    const parsed = ErrorSchema.safeParse(payload)
    throw parsed.success
      ? new TypeVaultError(toCode(parsed.data.error.code), parsed.data.error.message)
      : new TypeVaultError('unavailable', `daemon answered ${response.status}`)
  }
  const parsed = schema.safeParse(payload)
  if (!parsed.success) {
    throw new TypeVaultError('unavailable', 'the running typevault daemon does not match this CLI: restart it')
  }
  return parsed.data
}

/** The PID of the daemon answering on `socket`, or undefined when none answers (or it is too old to say). */
export async function servingPid(socket: string): Promise<number | undefined> {
  const Ping = z.object({ ok: z.literal(true), pid: z.number().int().positive() })
  try {
    return (await callDaemon(socket, '/v1/ping', {}, Ping, { timeoutMs: 1_000 })).pid
  } catch (error) {
    if (error instanceof TypeVaultError || error instanceof z.ZodError) return undefined
    if (error instanceof Error && error.name === 'TimeoutError') return undefined
    throw error
  }
}

/** The version the daemon answering on `socket` reports: undefined when none answers, null when it is too old to say. */
export async function servingVersion(socket: string): Promise<string | null | undefined> {
  const Ping = z.object({ ok: z.literal(true), version: z.string().optional() })
  try {
    return (await callDaemon(socket, '/v1/ping', {}, Ping, { timeoutMs: 1_000 })).version ?? null
  } catch (error) {
    if (error instanceof TypeVaultError || (error instanceof Error && error.name === 'TimeoutError')) return undefined
    throw error
  }
}

export async function isDaemonAlive(socket: string): Promise<boolean> {
  try {
    await callDaemon(socket, '/v1/ping', {}, z.object({ ok: z.literal(true) }), { timeoutMs: 1_000 })
    return true
  } catch (error) {
    if (error instanceof TypeVaultError || (error instanceof Error && error.name === 'TimeoutError')) return false
    throw error
  }
}
