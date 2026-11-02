import { afterEach, describe, expect, it, mock, spyOn } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { needsRefresh, refreshOAuth } from './refresh'

const now = new Date('2026-01-01T00:00:00.000Z')
const credentials = {
  access_token: 'old-access-value',
  refresh_token: 'refresh-value&with=symbols',
  client_id: 'example-client',
  client_secret: 'client-secret&with=symbols',
  expires_at: '2025-12-31T23:00:00.000Z',
  custom: 'preserved',
} as const

const servers: Bun.Server<undefined>[] = []

function endpoint(fetch: (request: Request) => Response | Promise<Response>): string {
  const server = Bun.serve({ port: 0, hostname: '127.0.0.1', fetch })
  servers.push(server)
  return server.url.href
}

afterEach(async () => {
  mock.restore()
  await Promise.all(servers.splice(0).map((server) => server.stop(true)))
})

describe('needsRefresh', () => {
  it.each([
    ['2025-12-31T23:59:59Z', undefined, true],
    ['2026-01-01T00:01:00Z', undefined, true],
    ['2026-01-01T00:01:00.001Z', undefined, false],
    ['2026-01-01T00:00:00Z', 0, true],
    ['2026-01-01T00:00:00.001Z', 0, false],
    ['2026-01-01T00:02:00Z', 120, true],
    ['2026-01-01T01:00:00+01:00', 0, true],
    ['not-a-date', undefined, false],
    ['2025-12-31', undefined, false],
  ] as const)('checks expiration %p with skew %p', (expires_at, skew, expected) => {
    expect(needsRefresh({ ...credentials, token_url: 'https://example.com/token', expires_at }, now, skew)).toBe(
      expected,
    )
  })

  it.each(['expires_at', 'refresh_token', 'token_url'])('requires %p to refresh', (key) => {
    const fields: Record<string, string> = { ...credentials, token_url: 'https://example.com/token' }
    delete fields[key]
    expect(needsRefresh(fields, now)).toBe(false)
  })
})

describe('refreshOAuth', () => {
  it.each([
    [true, true],
    [true, false],
    [false, true],
    [false, false],
  ])('refreshes with rotation=%p and expiry=%p', async (rotate, expires) => {
    const received = Promise.withResolvers<{
      readonly method: string
      readonly contentType: string | null
      readonly body: Readonly<Record<string, string>>
    }>()
    const token_url = endpoint(async (request) => {
      received.resolve({
        method: request.method,
        contentType: request.headers.get('content-type'),
        body: Object.fromEntries(new URLSearchParams(await request.text())),
      })
      return Response.json({
        access_token: 'new-access-value',
        ...(rotate ? { refresh_token: 'rotated-refresh-value' } : {}),
        ...(expires ? { expires_in: 3600 } : {}),
      })
    })
    const fields = Object.freeze({ ...credentials, token_url })

    const result = await refreshOAuth(fields, now)

    expect(await received.promise).toEqual({
      method: 'POST',
      contentType: 'application/x-www-form-urlencoded',
      body: {
        grant_type: 'refresh_token',
        refresh_token: credentials.refresh_token,
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
      },
    })
    expect(result).toEqual({
      access_token: 'new-access-value',
      refresh_token: rotate ? 'rotated-refresh-value' : credentials.refresh_token,
      client_id: credentials.client_id,
      client_secret: credentials.client_secret,
      custom: 'preserved',
      token_url,
      ...(expires ? { expires_at: '2026-01-01T01:00:00.000Z' } : {}),
    })
    expect(result).not.toBe(fields)
    expect(fields).toEqual({ ...credentials, token_url })
  })

  it('omits optional client credentials from the form', async () => {
    const received = Promise.withResolvers<string>()
    const token_url = endpoint(async (request) => {
      received.resolve(await request.text())
      return Response.json({ access_token: 'new-access-value', expires_in: 0 })
    })

    const result = await refreshOAuth({ refresh_token: 'refresh-value', token_url }, now)

    expect(Object.fromEntries(new URLSearchParams(await received.promise))).toEqual({
      grant_type: 'refresh_token',
      refresh_token: 'refresh-value',
    })
    expect(result['expires_at']).toBe(now.toISOString())
  })

  it.each([400, 302])('reports HTTP %p without exposing credentials or response content', async (status) => {
    const token_url = endpoint(() =>
      Response.json(
        { error: JSON.stringify(credentials) },
        { status, headers: { Location: 'http://example.com/token' } },
      ),
    )

    const error: unknown = await refreshOAuth({ ...credentials, token_url }, now).catch((error: unknown) => error)

    expect(error).toBeInstanceOf(TypeVaultError)
    if (!(error instanceof TypeVaultError)) throw error
    expect(error.code).toBe('unavailable')
    expect(error.message).toContain(String(status))
    for (const secret of [credentials.refresh_token, credentials.client_secret, credentials.access_token]) {
      expect(error.message).not.toContain(secret)
    }
  })

  it.each([
    '{invalid JSON containing refresh-value&with=symbols',
    '{}',
    '{"access_token":42}',
    '{"access_token":"new-access-value","expires_in":"3600"}',
    '{"access_token":"new-access-value","refresh_token":null}',
    '{"access_token":"new-access-value","expires_in":1e100}',
  ])('rejects malformed token responses: %p', async (body) => {
    const token_url = endpoint(() => new Response(body, { status: 200 }))

    const error: unknown = await refreshOAuth({ ...credentials, token_url }, now).catch((error: unknown) => error)

    expect(error).toBeInstanceOf(TypeVaultError)
    if (!(error instanceof TypeVaultError)) throw error
    expect(error.code).toBe('unavailable')
    expect(error.message).toContain('200')
    expect(error.message).not.toContain(credentials.refresh_token)
    expect(error.message).not.toContain('new-access-value')
  })

  it.each([
    'http://example.com/token',
    'http://localhost.example.com/token',
    'http://127.0.0.1.example.com/token',
    'http://[::2]/token',
    'ftp://localhost/token',
    'not-a-url',
  ])('rejects insecure or malformed token URLs: %p', async (token_url) => {
    await expect(refreshOAuth({ ...credentials, token_url }, now)).rejects.toMatchObject({ code: 'invalid' })
  })

  it('rejects missing refresh credentials', async () => {
    await expect(refreshOAuth({ token_url: 'https://example.com/token' }, now)).rejects.toMatchObject({
      code: 'invalid',
    })
  })

  it.each(['https://example.com/token', 'http://localhost/token', 'http://[::1]/token'])(
    'allows %p through URL validation and converts timeout errors',
    async (token_url) => {
      const timeout = spyOn(AbortSignal, 'timeout').mockReturnValue(
        AbortSignal.abort(new DOMException('credential-value', 'TimeoutError')),
      )

      const error: unknown = await refreshOAuth({ ...credentials, token_url }, now, { timeoutMs: 1234 }).catch(
        (error: unknown) => error,
      )

      expect(timeout).toHaveBeenCalledWith(1234)
      expect(error).toBeInstanceOf(TypeVaultError)
      if (!(error instanceof TypeVaultError)) throw error
      expect(error.code).toBe('unavailable')
      expect(error.message).not.toContain('credential-value')
    },
  )
})
