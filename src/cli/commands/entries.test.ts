import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { seal } from '../../core/crypto'

const CLI = join(import.meta.dir, '..', 'index.ts')
// Low-entropy values: anything derived from them in the output would be brute-forceable.
const PASSWORD = 'hunter2'
const PIN = '123456'

let base: string
let project: string
let env: Record<string, string>

async function cli(args: readonly string[], stdin?: string) {
  const proc = Bun.spawn([process.execPath, CLI, ...args], {
    cwd: project,
    env,
    stdin: stdin === undefined ? 'ignore' : new Blob([stdin]),
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

type PageRun = { readonly code: number; readonly output: string; readonly prompted: boolean }

// Runs `set`, filling the one-time page with `fields` if it shows one (or killing the command when `fields` is absent).
async function setViaPage(
  args: readonly string[],
  options: { readonly tty: boolean; readonly fields?: Record<string, string>; readonly typed?: string | undefined },
): Promise<PageRun> {
  let output = ''
  let prompted = false
  let submitted: Promise<void> = Promise.resolve()
  const onOutput = (text: string): void => {
    output += text
    const url = /http:\/\/127\.0\.0\.1:\d+\/r\/[A-Za-z0-9_-]{22}/.exec(output)?.[0]
    if (prompted || url === undefined || !/Match code: \w{6}/.test(output)) return
    prompted = true
    submitted =
      options.fields === undefined ? Promise.resolve(proc.kill()) : fillPage(url, args[0] ?? '', options.fields)
  }
  // Bun.spawn falls back to the system path when PATH is empty, so shadow the openers with no-op stubs instead.
  const stubs = join(base, 'stubs')
  mkdirSync(stubs, { recursive: true })
  for (const opener of ['open', 'xdg-open']) writeFileSync(join(stubs, opener), '#!/bin/sh\nexit 0\n', { mode: 0o755 })
  const spawnEnv = { ...env, PATH: stubs }
  const decoder = new TextDecoder()
  const proc = options.tty
    ? Bun.spawn([process.execPath, CLI, 'set', ...args], {
        cwd: project,
        env: spawnEnv,
        terminal: { cols: 200, rows: 40, data: (_terminal, data) => onOutput(decoder.decode(data)) },
      })
    : Bun.spawn([process.execPath, CLI, 'set', ...args], {
        cwd: project,
        env: spawnEnv,
        stdin: 'ignore',
        stdout: 'pipe',
        stderr: 'pipe',
      })
  if (options.typed !== undefined) proc.terminal?.write(`${options.typed}\n\u0004`)
  if (proc.stderr instanceof ReadableStream) {
    for await (const chunk of proc.stderr) onOutput(decoder.decode(chunk))
  }
  const code = await proc.exited
  await submitted
  return { code, output, prompted }
}

async function fillPage(url: string, name: string, fields: Record<string, string>): Promise<void> {
  const page = await (await fetch(url)).text()
  const data = /<script type="application\/json" id="tv-data">(.*?)<\/script>/s.exec(page)?.[1] ?? ''
  const view = JSON.parse(data) as { type: string; recipients: string[] }
  const now = new Date().toISOString()
  const payload = { v: 1, name, type: view.type, fields, tags: [], created: now, rotated: now }
  const ciphertext = await seal(view.recipients, new TextEncoder().encode(JSON.stringify(payload)))
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: new Uint8Array(ciphertext),
  })
  expect(response.status).toBe(204)
}

function expectNothingDerivedFrom(output: string, secret: string): void {
  const digest = new Bun.CryptoHasher('sha256').update(secret).digest('hex')
  expect(output).not.toContain(secret)
  expect(output).not.toContain(digest.slice(0, 8))
  expect(output).not.toContain(`${secret.length} chars`)
}

beforeEach(async () => {
  base = realpathSync(mkdtempSync(join(tmpdir(), 'typevault-cli-get-')))
  project = join(base, 'project')
  mkdirSync(project)
  env = { PATH: process.env['PATH'] ?? '', XDG_CONFIG_HOME: join(base, 'config') }
  expect((await cli(['init', '--machine'])).code).toBe(0)
  const fields = JSON.stringify({ username: 'alice', password: PASSWORD, PIN })
  expect((await cli(['set', 'tv://svc', '--type', 'password', '--stdin-json'], fields)).code).toBe(0)
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

it.each([
  ['the main field', 'tv://svc', PASSWORD],
  ['a custom field', 'tv://svc#PIN', PIN],
])('refuses to print %s without --reveal and leaks nothing about it', async (_, ref, secret) => {
  // when
  const result = await cli(['get', ref])

  // then
  expect(result.code).not.toBe(0)
  expect(result.stdout).toBe('')
  expect(result.stderr).toContain('--reveal')
  expectNothingDerivedFrom(result.stderr, secret)
})

it('prints a secret field with --reveal', async () => {
  expect(await cli(['get', 'tv://svc#PIN', '--reveal'])).toMatchObject({ code: 0, stdout: `${PIN}\n` })
})

it('prints a plain field without --reveal', async () => {
  expect(await cli(['get', 'tv://svc#username'])).toMatchObject({ code: 0, stdout: 'alice\n' })
})

it('redacts secret fields in --json without --reveal and leaks nothing about them', async () => {
  // when
  const result = await cli(['get', 'tv://svc', '--json'])

  // then
  expect(result.code).toBe(0)
  expect(JSON.parse(result.stdout)).toEqual({ username: 'alice', password: '<redacted>', PIN: '<redacted>' })
  for (const secret of [PASSWORD, PIN]) expectNothingDerivedFrom(result.stdout + result.stderr, secret)
})

const WEB_KEY = 'sk-web-test-1'

it('prompts on the page for a new entry from a terminal and stores what was typed there', async () => {
  // when
  const result = await setViaPage(['tv://web', '--type', 'api_key'], { tty: true, fields: { key: WEB_KEY } })

  // then
  expect(result).toMatchObject({ code: 0, prompted: true })
  expect(result.output).not.toContain(WEB_KEY)
  expect(await cli(['get', 'tv://web', '--reveal'])).toMatchObject({ code: 0, stdout: `${WEB_KEY}\n` })
})

it('prompts with --web without a terminal', async () => {
  // when
  const result = await setViaPage(['tv://web', '--type', 'api_key', '--web'], { tty: false, fields: { key: WEB_KEY } })

  // then
  expect(result).toMatchObject({ code: 0, prompted: true })
  expect(result.output).not.toContain(WEB_KEY)
  expect(await cli(['get', 'tv://web', '--reveal'])).toMatchObject({ code: 0, stdout: `${WEB_KEY}\n` })
})

it.each([
  ['--no-web', ['tv://web', '--type', 'api_key', '--no-web'], undefined],
  ['an existing entry', ['tv://svc', '--field', 'username=bob'], undefined],
  ['--stdin', ['tv://web', '--type', 'api_key', '--stdin'], WEB_KEY],
])('does not prompt from a terminal with %s', async (_, args, typed) => {
  expect(await setViaPage(args, { tty: true, typed })).toMatchObject({ code: 0, prompted: false })
})
