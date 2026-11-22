import { afterEach, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { z } from 'zod'

import { callDaemon } from './client'

const roots: string[] = []
const servers: Bun.Server<undefined>[] = []

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.stop(true)))
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

it('maps a transport timeout to a TypeVaultError', async () => {
  const root = mkdtempSync(join(tmpdir(), 'typevault-client-'))
  roots.push(root)
  const socket = join(root, 'daemon.sock')
  const received = Promise.withResolvers<void>()
  const pending = Promise.withResolvers<Response>()
  servers.push(
    Bun.serve({
      unix: socket,
      fetch() {
        received.resolve()
        return pending.promise
      },
    }),
  )

  const call = callDaemon(socket, '/v1/wait', {}, z.unknown(), { timeoutMs: 10 })
  await received.promise

  try {
    await expect(call).rejects.toMatchObject({
      code: 'unavailable',
      cause: { name: 'TimeoutError' },
    })
  } finally {
    pending.resolve(Response.json({ ok: true }))
  }
})

it('maps an incompatible daemon response to a TypeVaultError', async () => {
  const root = mkdtempSync(join(tmpdir(), 'typevault-client-'))
  roots.push(root)
  const socket = join(root, 'daemon.sock')
  servers.push(
    Bun.serve({
      unix: socket,
      fetch: () => Response.json({ id: 'request-id', url: 'https://vault.example.test', code: 'MAPLE-74' }),
    }),
  )

  await expect(
    callDaemon(
      socket,
      '/v1/request',
      {},
      z.object({ id: z.string(), url: z.string(), code: z.string(), expiresAt: z.number() }),
    ),
  ).rejects.toMatchObject({ code: 'unavailable' })
})

it('treats a reply cut off after its headers as lost in transport, unlike a daemon rejection', async () => {
  // given a daemon whose reply breaks off partway, and one that rejects the request
  const root = mkdtempSync(join(tmpdir(), 'typevault-client-'))
  roots.push(root)
  const [cut, rejecting] = [join(root, 'cut.sock'), join(root, 'rejecting.sock')]
  servers.push(
    Bun.serve({
      unix: cut,
      fetch: () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode('{"change":"abc'))
              controller.close()
            },
          }),
          { headers: { 'content-type': 'application/json' } },
        ),
    }),
    Bun.serve({
      unix: rejecting,
      fetch: () => Response.json({ error: { code: 'unavailable', message: 'internal daemon error' } }, { status: 500 }),
    }),
  )

  // then the cut-off reply carries its transport cause, and the rejection none
  await expect(callDaemon(cut, '/v1/admin', {}, z.unknown())).rejects.toMatchObject({
    code: 'unavailable',
    cause: expect.any(Error),
  })
  const rejection = await callDaemon(rejecting, '/v1/admin', {}, z.unknown()).catch((error: unknown) => error)
  expect(rejection).toMatchObject({ code: 'unavailable', message: 'internal daemon error' })
  expect((rejection as Error).cause).toBeUndefined()
})
