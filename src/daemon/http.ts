import type { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import type { ErrorCode } from '../core/errors'

const STATUS: Readonly<Record<ErrorCode, number>> = {
  invalid: 400,
  denied: 403,
  not_found: 404,
  conflict: 409,
  expired: 410,
  tampered: 422,
  locked: 423,
  unavailable: 503,
  in_use: 423,
  no_vault: 404,
  not_member: 403,
}

export const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

export function errorResponse(error: unknown): Response {
  if (error instanceof TypeVaultError)
    return json({ error: { code: error.code, message: error.message } }, STATUS[error.code])
  // Unexpected failures stay out of responses: they may carry details an agent shouldn't see.
  console.error('typevault daemon: unexpected error', error)
  return json({ error: { code: 'unavailable', message: 'internal daemon error' } }, 500)
}

export async function parseBody<T>(request: Request, schema: z.ZodType<T>): Promise<T> {
  const text = await request.text()
  let body: unknown
  try {
    body = text === '' ? {} : JSON.parse(text)
  } catch (error) {
    if (error instanceof SyntaxError) throw new TypeVaultError('invalid', 'request body is not JSON')
    throw error
  }
  const parsed = schema.safeParse(body)
  if (!parsed.success)
    throw new TypeVaultError('invalid', `bad request: ${parsed.error.issues[0]?.message ?? 'invalid'}`)
  return parsed.data
}

export type Handler = (request: Request) => Promise<Response>

/** Exact-match POST routing; anything else is a 404. */
export function router(routes: Readonly<Record<string, Handler>>): (request: Request) => Promise<Response> {
  return async (request) => {
    const handler = routes[new URL(request.url).pathname]
    if (request.method !== 'POST' || handler === undefined)
      return json({ error: { code: 'not_found', message: 'no such route' } }, 404)
    try {
      return await handler(request)
    } catch (error) {
      return errorResponse(error)
    }
  }
}
