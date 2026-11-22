import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import type { z } from 'zod'

import { randomToken } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { ownerChange } from './owner-change'

let run: string
let servers: Bun.Server<undefined>[] = []
beforeEach(() => {
  run = mkdtempSync(join(tmpdir(), 'tvoc-'))
})
afterEach(async () => {
  await Promise.all(servers.map((server) => server.stop(true)))
  servers = []
  rmSync(run, { recursive: true, force: true })
})

// The daemon's agent socket, still answering pings while its replies get lost.
function alive(): { run: string; agentSocket: string } {
  const agentSocket = join(run, 'agent.sock')
  servers.push(Bun.serve({ unix: agentSocket, fetch: () => Response.json({ ok: true }) }))
  return { run, agentSocket }
}

const outcome = { affected: ['openai'], removed: [], ownerRotated: true, unserved: [], scopeRefreshed: true }
const lost = () =>
  new TypeVaultError('unavailable', 'the typevault daemon reply was cut off', { cause: new Error('cut') })

// A daemon that answers each route from a script, in order, and records what it was asked.
function daemon(script: Record<string, (() => unknown)[]>) {
  const asked: string[] = []
  const access = {
    call: async <T>(path: string, _body: unknown, schema: z.ZodType<T>): Promise<T> => {
      asked.push(path)
      const answer = script[path]?.shift()
      if (answer === undefined) throw new Error(`unexpected ${path}`)
      return schema.parse(answer())
    },
  }
  return { access, asked }
}

it('collects a change whose admission answer was lost, without sending it again', async () => {
  // given a daemon that took the change but whose answer was lost, and that would now refuse it as new (the owner rotated)
  const change = randomToken(16)
  const { access, asked } = daemon({
    '/v1/admin': [
      () => {
        throw lost()
      },
      () => {
        throw new TypeVaultError('locked', 'the vault owner rotated')
      },
    ],
    '/v1/admin/wait': [() => ({ done: false }), () => ({ done: true, result: outcome })],
  })

  // then the change is collected by its id, and the admission was sent once
  expect(await ownerChange(access, alive(), { change })).toEqual(outcome)
  expect(asked).toEqual(['/v1/admin', '/v1/admin/wait', '/v1/admin/wait'])
})

it('sends an admission again only after the daemon shows it never arrived', async () => {
  const change = randomToken(16)
  const { access, asked } = daemon({
    '/v1/admin': [
      () => {
        throw lost()
      },
      () => ({ change }),
    ],
    '/v1/admin/wait': [
      () => {
        throw new TypeVaultError('not_found', 'no such owner change')
      },
      () => ({ done: true, result: outcome }),
    ],
  })
  expect(await ownerChange(access, alive(), { change })).toEqual(outcome)
  expect(asked).toEqual(['/v1/admin', '/v1/admin/wait', '/v1/admin', '/v1/admin/wait'])
})

it('reports the outcome as unknown once the daemon is gone and kept none', async () => {
  const change = randomToken(16)
  const { access } = daemon({
    '/v1/admin': [
      () => {
        throw lost()
      },
    ],
  })
  await expect(ownerChange(access, { run, agentSocket: join(run, 'agent.sock') }, { change })).rejects.toMatchObject({
    code: 'unavailable',
    message: expect.stringContaining('outcome is unknown'),
  })
})
