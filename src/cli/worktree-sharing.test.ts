import { expect, it } from 'bun:test'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { encodeSecretKey } from '../core/crypto'
import { readIdentity, unlockIdentity } from '../core/identity'
import { localLayout } from '../core/layout'
import { callDaemon } from '../daemon/client'
import {
  addWorktree,
  base,
  CLI,
  cli,
  git,
  LOCKED,
  main,
  owner,
  PASSWORD,
  succeeds,
  untilText,
} from './worktree.harness'

it('refuses to share the session through a grant derived from it', async () => {
  // given a worktree, and an agent's grant derived from the unlocked session
  const worktree = join(base, 'wt')
  succeeds(await git(['worktree', 'add', '-q', worktree], main))
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  const layout = localLayout(join(main, '.typevault'), owner)
  const session = readFileSync(layout.sessionFile, 'utf8').trim()
  const Derived = z.object({ token: z.string() })
  const { token } = await callDaemon(layout.agentSocket, '/v1/derive', { only: [] }, Derived, { token: session })

  // when that grant asks to share the session with the worktree
  const attach = callDaemon(layout.agentSocket, '/v1/attach', { vault: join(worktree, '.typevault') }, z.unknown(), {
    token,
  })

  // then it is refused, and the worktree stays locked
  await expect(attach).rejects.toMatchObject({ code: 'denied' })
  expect(existsSync(localLayout(join(worktree, '.typevault'), owner).sessionFile)).toBe(false)
}, 60_000)

it('starts a shared session where nothing in the worktree runs with it', async () => {
  // given a worktree whose bunfig.toml preloads a script, as an agent working there could add
  const worktree = await addWorktree()
  const marker = join(base, 'preloaded')
  writeFileSync(
    join(worktree, 'capture.ts'),
    `import { writeFileSync } from 'node:fs'\nif (process.argv.includes('--key-stdin')) writeFileSync(${JSON.stringify(marker)}, 'ran')\n`,
  )
  writeFileSync(join(worktree, 'bunfig.toml'), 'preload = ["./capture.ts"]\n')
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))

  // when an agent there reads through the shared session
  succeeds(await cli(['ls'], worktree))

  // then the session holding the key started without running it
  expect(existsSync(marker)).toBe(false)
}, 60_000)

it('leaves no worktree unlocked when the session is locked while sharing with it', async () => {
  // given a worktree, and the vault unlocked in the main checkout
  const worktree = await addWorktree()
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))

  // when the worktree's first read and a lock in the main checkout run at once
  await Promise.all([cli(['ls'], worktree), cli(['lock'], main)])

  // then neither is left unlocked
  expect((await cli(['ls'], worktree)).stderr).toContain(LOCKED)
  expect((await cli(['ls'], main)).stderr).toContain(LOCKED)
}, 60_000)

it('ends a shared session when the session it came from dies without cleanup', async () => {
  // given a worktree reading through a session shared from the main checkout's
  const worktree = await addWorktree()
  const identity = readIdentity(owner)
  if (identity === undefined) throw new Error('no identity')
  const key = encodeSecretKey(await unlockIdentity(identity, PASSWORD))
  const vault = join(main, '.typevault')
  const source = Bun.spawn([process.execPath, CLI, 'daemon', 'run', '--vault', vault, '--key-stdin', '--ttl', '10m'], {
    cwd: base,
    env: owner,
    stdin: new TextEncoder().encode(key),
    stdout: 'ignore',
    stderr: 'pipe',
  })
  await untilText(source.stderr, 'typevault daemon ready')
  succeeds(await cli(['ls'], worktree))

  // when that session's daemon is killed, with no chance to stop the worktree's
  source.kill('SIGKILL')
  await source.exited

  // then the worktree's session serves nothing more
  expect((await cli(['ls'], worktree)).stderr).toContain(LOCKED)
}, 60_000)
