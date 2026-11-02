import { afterEach, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'

import { TypeVaultError } from '../core/errors'
import { startPromptServer, type PromptServer, type PromptView } from './index'

let server: PromptServer | undefined

const view: PromptView = {
  name: 'stripe',
  type: 'api_key',
  group: 'trusted',
  reason: '<img src=x onerror=alert(1)>',
  requester: 'test-grant',
  code: 'MAPLE-74',
  recipients: ['age1test'],
  expiresAt: new Date('2100-01-01T00:00:00.000Z'),
}

afterEach(async () => {
  await server?.stop()
  server = undefined
})

async function fixture() {
  server = await startPromptServer()
  const handle = server.open(view)
  // Observe rejection before teardown or synchronous expiry, while preserving the original done promise.
  const outcome = handle.done.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  )
  return { server, handle, outcome }
}

function securityHeaders(response: Response): void {
  expect(response.headers.get('referrer-policy')).toBe('no-referrer')
  expect(response.headers.get('x-frame-options')).toBe('DENY')
  expect(response.headers.get('cache-control')).toBe('no-store')
  expect(response.headers.get('x-content-type-options')).toBe('nosniff')
  const csp = response.headers.get('content-security-policy') ?? ''
  for (const directive of [
    "default-src 'none'",
    "connect-src 'self'",
    'img-src data:',
    "form-action 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ])
    expect(csp.split('; ')).toContain(directive)
}

function upload(url: string, body: Uint8Array = new Uint8Array([0, 255, 42])): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: new Uint8Array(body),
  })
}

function expectExpired(result: unknown): void {
  expect(result).toEqual({ error: expect.any(TypeVaultError) })
  if (typeof result !== 'object' || result === null || !('error' in result)) {
    throw new TypeVaultError('invalid', 'Expected rejected prompt')
  }
  expect(result.error).toMatchObject({ code: 'expired' })
}

test('page security hashes authorize the exact executable script and stylesheet bytes', async () => {
  const { handle } = await fixture()
  const response = await fetch(handle.url)
  expect(response.status).toBe(200)
  securityHeaders(response)
  const html = await response.text()
  const script = /<script type="module">([\s\S]*?)<\/script>/.exec(html)?.[1]
  const style = /<style>([\s\S]*?)<\/style>/.exec(html)?.[1]
  expect(script).toBeString()
  expect(style).toBeString()
  const csp = response.headers.get('content-security-policy') ?? ''
  for (const [kind, bytes] of [
    ['script', script],
    ['style', style],
  ]) {
    if (bytes === undefined) throw new TypeVaultError('invalid', 'Missing inline asset')
    expect(csp).toContain(`${kind}-src 'sha256-${createHash('sha256').update(bytes).digest('base64')}'`)
  }
})

test('untrusted text is escaped in markup and cannot terminate embedded JSON', async () => {
  const { server } = await fixture()
  const hostile = '</script><img src=x onerror=alert(1)>'
  const handle = server.open({ ...view, name: hostile, requester: hostile, group: hostile, code: hostile })
  const outcome = handle.done.then(
    () => undefined,
    (error: unknown) => error,
  )
  const html = await (await fetch(handle.url)).text()
  expect(html).not.toContain('<img')
  expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
  const data = /<script type="application\/json" id="tv-data">([\s\S]*?)<\/script>/.exec(html)?.[1]
  if (data === undefined) throw new TypeVaultError('invalid', 'Missing JSON data')
  expect(data).not.toContain('<')
  expect(JSON.parse(data)).toMatchObject({ name: hostile, reason: view.reason, requester: hostile })
  server.cancel(handle.id)
  await outcome
})

test('POST returns 204 and delivers exact bytes only once', async () => {
  const { handle } = await fixture()
  const bytes = new Uint8Array([0, 255, 13, 10, 128, 42])
  const response = await upload(handle.url, bytes)
  expect(response.status).toBe(204)
  expect(await response.text()).toBe('')
  securityHeaders(response)
  expect(await handle.done).toEqual(bytes)
  for (const response of [await upload(handle.url), await fetch(handle.url)]) {
    expect(response.status).toBe(410)
    securityHeaders(response)
  }
})

test('concurrent submissions have exactly one successful winner', async () => {
  const { handle } = await fixture()
  const responses = await Promise.all([upload(handle.url), upload(handle.url)])
  expect(responses.map((response) => response.status).sort()).toEqual([204, 410])
})

test('unknown tokens unsupported methods and other routes return empty 404 responses', async () => {
  const { handle, server } = await fixture()
  const origin = `http://127.0.0.1:${server.port}`
  for (const [url, method] of [
    [`${origin}/r/${'x'.repeat(22)}`, 'GET'],
    [`${origin}/r/${'x'.repeat(22)}`, 'POST'],
    [`${origin}/`, 'GET'],
    [`${handle.url}/extra`, 'GET'],
    [handle.url, 'PUT'],
    [handle.url, 'OPTIONS'],
  ]) {
    if (url === undefined || method === undefined) throw new TypeVaultError('invalid', 'Missing route fixture')
    const response = await fetch(url, { method })
    expect(response.status).toBe(404)
    expect(await response.text()).toBe('')
    securityHeaders(response)
  }
})

test('body limit allows 64 KiB and rejects larger fixed and streamed uploads without consuming the token', async () => {
  const { handle } = await fixture()
  expect((await upload(handle.url, new Uint8Array(65_537))).status).toBe(413)
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(32_768))
      controller.enqueue(new Uint8Array(32_769))
      controller.close()
    },
  })
  const tooLarge = await fetch(handle.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: stream,
  })
  expect(tooLarge.status).toBe(413)
  securityHeaders(tooLarge)
  const bytes = new Uint8Array(65_536).fill(42)
  expect((await upload(handle.url, bytes)).status).toBe(204)
  expect(await handle.done).toEqual(bytes)
})

test('wrong content type cannot consume a request', async () => {
  const { handle } = await fixture()
  const response = await fetch(handle.url, { method: 'POST', body: 'plaintext is not accepted' })
  expect(response.status).toBe(415)
  securityHeaders(response)
  expect((await fetch(handle.url)).status).toBe(200)
})

test('already expired requests reject done and serve 410', async () => {
  server = await startPromptServer()
  const handle = server.open({ ...view, expiresAt: new Date(0) })
  const outcome = handle.done.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  )
  expectExpired(await outcome)
  const response = await fetch(handle.url)
  expect(response.status).toBe(410)
  securityHeaders(response)
})

test('cancel rejects done and invalidates both routes', async () => {
  const { server, handle, outcome } = await fixture()
  server.cancel(handle.id)
  server.cancel(handle.id)
  expectExpired(await outcome)
  expect((await fetch(handle.url)).status).toBe(410)
  expect((await upload(handle.url)).status).toBe(410)
})

test('stop rejects pending requests closes listener and prevents reopening', async () => {
  const { server, handle, outcome } = await fixture()
  await server.stop()
  expectExpired(await outcome)
  expect(() => server.open(view)).toThrow(TypeVaultError)
  await expect(fetch(handle.url)).rejects.toThrow()
})

test('public URL overrides address while id remains separate from the token', async () => {
  server = await startPromptServer({ publicUrl: 'https://vault.example.test' })
  const handle = server.open(view)
  const outcome = handle.done.then(
    () => undefined,
    (error: unknown) => error,
  )
  expect(handle.url).toMatch(/^https:\/\/vault\.example\.test\/r\/[A-Za-z0-9_-]{22}$/)
  expect(handle.id).not.toBe(handle.url.split('/').at(-1))
  server.cancel(handle.id)
  await outcome
})
