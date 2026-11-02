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
    if (error instanceof Error && error.name !== 'TimeoutError') {
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
  return schema.parse(payload)
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
