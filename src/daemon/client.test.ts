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
