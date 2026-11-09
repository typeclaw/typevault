import { expect, it } from 'bun:test'
import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { localLayout } from '../core/layout'
import { callDaemon, servingPid } from '../daemon/client'
import { addWorktree, base, cli, main, owner, PASSWORD, succeeds } from './worktree.harness'

it('unlocks a copied repository with its own password instead of sharing a session (#56)', async () => {
  const worktree = await addWorktree()
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  succeeds(await cli(['ls'], worktree))
  const copy = join(base, 'copy')
  cpSync(main, copy, { recursive: true })
  const layout = localLayout(join(copy, '.typevault'), owner)

  try {
    expect((await cli(['ls'], copy)).code).toBe(1)
    expect(existsSync(layout.sessionFile)).toBe(false)
    const read = succeeds(await cli(['get', 'openai', '--reveal', '--vault-password-stdin'], copy, `${PASSWORD}\n`))
    expect(read.stdout.trim()).toBe('sk-test-1')
  } finally {
    await cli(['lock'], copy)
  }
}, 60_000)

it.each(['main', 'worktree'])(
  'keeps sessions alive after locking a copied %s (#56)',
  async (checkout) => {
    const worktree = await addWorktree()
    succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))
    succeeds(await cli(['ls'], worktree))
    const socket = localLayout(join(worktree, '.typevault'), owner).agentSocket
    const pid = await servingPid(socket)
    expect(pid).toBeNumber()
    const copy = join(base, 'copy')
    cpSync(checkout === 'main' ? main : worktree, copy, { recursive: true })

    succeeds(await cli(['lock'], copy))

    expect(await servingPid(socket)).toBe(pid)
  },
  60_000,
)

it('falls back to its own unlock when a worktree has a different owner (#56)', async () => {
  const worktree = await addWorktree()
  rmSync(join(worktree, '.typevault'), { recursive: true })
  succeeds(await cli(['init', '--name', 'alice', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  const source = localLayout(join(main, '.typevault'), owner)
  const target = localLayout(join(worktree, '.typevault'), owner)
  const token = readFileSync(source.sessionFile, 'utf8').trim()

  await expect(
    callDaemon(source.agentSocket, '/v1/attach', { vault: target.vault }, z.unknown(), { token }),
  ).rejects.toMatchObject({ code: 'tampered' })
  expect((await cli(['ls'], worktree)).code).toBe(1)
  expect(existsSync(target.sessionFile)).toBe(false)
  expect(
    JSON.parse(succeeds(await cli(['ls', '--json', '--vault-password-stdin'], worktree, `${PASSWORD}\n`)).stdout),
  ).toEqual([])
}, 60_000)

it.each(['denied', 'expired', 'unavailable'])(
  'unlocks after attach refuses with %s (#56)',
  async (code) => {
    const worktree = await addWorktree()
    const source = localLayout(join(main, '.typevault'), owner)
    writeFileSync(source.sessionFile, 'test-session')
    const server = Bun.serve({
      unix: source.agentSocket,
      fetch: (request) =>
        new URL(request.url).pathname === '/v1/ping'
          ? Response.json({ ok: true })
          : Response.json({ error: { code, message: 'test refusal' } }, { status: 403 }),
    })
    try {
      const read = succeeds(
        await cli(['get', 'openai', '--reveal', '--vault-password-stdin'], worktree, `${PASSWORD}\n`),
      )
      expect(read.stdout.trim()).toBe('sk-test-1')
    } finally {
      await server.stop(true)
      rmSync(source.sessionFile, { force: true })
      await cli(['lock'], worktree)
    }
  },
  60_000,
)
