import { afterEach, beforeEach, expect } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
export const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

export const CLI = join(import.meta.dir, 'index.ts')
export const PASSWORD = 'correct horse battery staple'

export type Run = { readonly code: number; readonly stdout: string; readonly stderr: string }

export let base: string
export let main: string
export let owner: Record<string, string>

export async function run(command: readonly string[], cwd: string, stdin = ''): Promise<Run> {
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

export const cli = (args: readonly string[], cwd: string, stdin = ''): Promise<Run> =>
  run([process.execPath, CLI, ...args], cwd, stdin)

export const git = (args: readonly string[], cwd: string): Promise<Run> =>
  run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.com', '-c', 'commit.gpgsign=false', ...args], cwd)

export const succeeds = (result: Run): Run => {
  expect({ code: result.code, stderr: result.code === 0 ? '' : result.stderr }).toEqual({ code: 0, stderr: '' })
  return result
}

export const LOCKED = 'the vault is locked'

export async function untilText(stream: ReadableStream<Uint8Array>, text: string): Promise<void> {
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

export async function addWorktree(): Promise<string> {
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
  succeeds(await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], main, 'sk-test-1'))
  succeeds(await cli(['lock'], main))
  succeeds(await git(['init', '-q'], main))
  succeeds(await git(['add', '-A'], main))
  succeeds(await git(['commit', '-q', '-m', 'vault'], main))
})

afterEach(async () => {
  await cli(['lock'], main)
  rmSync(base, { recursive: true, force: true })
})
