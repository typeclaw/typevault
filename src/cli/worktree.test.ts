import { afterEach, beforeEach, expect, it } from 'bun:test'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { z } from 'zod'

import { encodeSecretKey } from '../core/crypto'
import { readIdentity, unlockIdentity } from '../core/identity'
import { localLayout } from '../core/layout'
import { callDaemon } from '../daemon/client'

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

const CLI = join(import.meta.dir, 'index.ts')
const PASSWORD = 'correct horse battery staple'

type Run = { readonly code: number; readonly stdout: string; readonly stderr: string }

let base: string
let main: string
let owner: Record<string, string>

async function run(command: readonly string[], cwd: string, stdin = ''): Promise<Run> {
  const proc = Bun.spawn([...command], {
    cwd,
    env: owner,
    stdin: new TextEncoder().encode(stdin),
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const [code, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])
  return { code, stdout, stderr }
}

const cli = (args: readonly string[], cwd: string, stdin = ''): Promise<Run> =>
  run([process.execPath, CLI, ...args], cwd, stdin)

const git = (args: readonly string[], cwd: string): Promise<Run> =>
  run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.com', '-c', 'commit.gpgsign=false', ...args], cwd)

const succeeds = (result: Run): Run => {
  expect({ code: result.code, stderr: result.code === 0 ? '' : result.stderr }).toEqual({ code: 0, stderr: '' })
  return result
}

const LOCKED = 'the vault is locked'

async function untilText(stream: ReadableStream<Uint8Array>, text: string): Promise<void> {
  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let seen = ''
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) throw new Error(`the stream ended before "${text}": ${seen}`)
      seen += decoder.decode(value, { stream: true })
      if (seen.includes(text)) return
    }
  } finally {
    reader.releaseLock()
  }
}

async function addWorktree(): Promise<string> {
  const worktree = join(base, 'wt')
  succeeds(await git(['worktree', 'add', '-q', worktree], main))
  return worktree
}

beforeEach(async () => {
  base = realpathSync(mkdtempSync(join(SHORT_TMP, 'tvw-')))
  main = join(base, 'main')
  mkdirSync(main)
  owner = { PATH: process.env['PATH'] ?? '', HOME: base, XDG_CONFIG_HOME: join(base, 'alice') }
  succeeds(await cli(['init', '--name', 'alice', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  succeeds(await cli(['set', 'tv://openai', '--preset', 'api_key', '--stdin'], main, 'sk-test-1'))
  succeeds(await cli(['lock'], main))
  succeeds(await git(['init', '-q'], main))
  succeeds(await git(['add', '-A'], main))
  succeeds(await git(['commit', '-q', '-m', 'vault'], main))
})

afterEach(async () => {
  await cli(['lock'], main)
  rmSync(base, { recursive: true, force: true })
})

it('shares a session unlocked in one worktree with the others, and locks them together', async () => {
  // given a linked worktree of the repository, and the vault unlocked in the main one
  const worktree = join(base, 'wt')
  succeeds(await git(['worktree', 'add', '-q', worktree], main))
  expect((await cli(['ls'], worktree)).stderr).toContain(LOCKED)
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))

  // when an agent reads in the worktree, with no password to give
  const read = succeeds(await cli(['ls', '--json'], worktree))

  // then it reads the worktree's own vault through the shared session
  expect(JSON.parse(read.stdout)).toMatchObject([{ name: 'openai' }])

  // and locking in the worktree locks the main one too, so nothing is shared back
  expect(succeeds(await cli(['lock'], worktree)).stdout).toBe('locked\n')
  expect((await cli(['ls'], main)).stderr).toContain(LOCKED)
  expect((await cli(['ls'], worktree)).stderr).toContain(LOCKED)
}, 60_000)

it('shares no session with a copy of the vault or a clone of the repository', async () => {
  // given the vault unlocked in the repository, a clone of it, and a bare copy of the vault
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  const clone = join(base, 'clone')
  succeeds(await git(['clone', '-q', main, clone], base))
  const copy = join(base, 'copy')
  cpSync(join(main, '.typevault'), join(copy, '.typevault'), { recursive: true })

  // then both stay locked
  expect((await cli(['ls'], clone)).stderr).toContain(LOCKED)
  expect((await cli(['ls'], copy)).stderr).toContain(LOCKED)

  // and the session refuses to start in either, even asked directly with its own token
  const layout = localLayout(join(main, '.typevault'), owner)
  const token = readFileSync(layout.sessionFile, 'utf8').trim()
  const Ok = z.object({ ok: z.literal(true) })
  for (const vault of [join(clone, '.typevault'), join(copy, '.typevault')]) {
    await expect(callDaemon(layout.agentSocket, '/v1/attach', { vault }, Ok, { token })).rejects.toMatchObject({
      code: 'denied',
    })
  }
}, 60_000)

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
