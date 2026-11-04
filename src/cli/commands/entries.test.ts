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
  // End of input is ^D on a Unix terminal, ^Z then Enter on a Windows console.
  const eof = process.platform === 'win32' ? '\r\u001a\r' : '\n\u0004'
  if (options.typed !== undefined) proc.terminal?.write(`${options.typed}${eof}`)
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
  const payload = {
    v: 1,
    name,
    fields: Object.fromEntries(Object.entries(fields).map(([key, value]) => [key, { type: 'secret', value }])),
    tags: [],
    created: now,
    rotated: now,
  }
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
  expect((await cli(['set', 'tv://svc', '--preset', 'password', '--stdin-json'], fields)).code).toBe(0)
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

it.each([
  ['the password field', 'tv://svc#password', PASSWORD],
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
  expect(JSON.parse(result.stdout)).toEqual({
    username: { type: 'text', value: 'alice' },
    password: { type: 'secret', value: '<redacted>' },
    PIN: { type: 'secret', value: '<redacted>' },
  })
  for (const secret of [PASSWORD, PIN]) expectNothingDerivedFrom(result.stdout + result.stderr, secret)
})

const WEB_KEY = 'sk-web-test-1'

it('prompts on the page for a new entry from a terminal and stores what was typed there', async () => {
  // when
  const result = await setViaPage(['tv://web', '--preset', 'api_key'], { tty: true, fields: { $default: WEB_KEY } })

  // then
  expect(result).toMatchObject({ code: 0, prompted: true })
  expect(result.output).not.toContain(WEB_KEY)
  expect(await cli(['get', 'tv://web', '--reveal'])).toMatchObject({ code: 0, stdout: `${WEB_KEY}\n` })
})

it('prompts with --web without a terminal', async () => {
  // when
  const result = await setViaPage(['tv://web', '--preset', 'api_key', '--web'], {
    tty: false,
    fields: { $default: WEB_KEY },
  })

  // then
  expect(result).toMatchObject({ code: 0, prompted: true })
  expect(result.output).not.toContain(WEB_KEY)
  expect(await cli(['get', 'tv://web', '--reveal'])).toMatchObject({ code: 0, stdout: `${WEB_KEY}\n` })
})

it.each([
  ['--no-web', ['tv://web', '--preset', 'api_key', '--no-web'], undefined],
  ['an existing entry', ['tv://svc', '--field', 'username=bob'], undefined],
  ['--stdin', ['tv://web', '--preset', 'api_key', '--stdin'], WEB_KEY],
])('does not prompt from a terminal with %s', async (_, args, typed) => {
  expect(await setViaPage(args, { tty: true, typed })).toMatchObject({ code: 0, prompted: false })
})

it('stores a value without a preset and resolves its bare reference', async () => {
  expect(await cli(['set', 'tv://simple', '--stdin'], 'private-value')).toMatchObject({ code: 0 })
  const result = await cli(['get', 'tv://simple', '--json', '--reveal'])
  expect(JSON.parse(result.stdout)).toEqual({ $default: { type: 'secret', value: 'private-value' } })
  expect(await cli(['get', 'tv://simple', '--reveal'])).toMatchObject({ code: 0, stdout: 'private-value\n' })
})
it('lists fields when a bare login reference is ambiguous', async () => {
  const result = await cli(['get', 'tv://svc', '--reveal'])
  expect(result.code).toBe(1)
  expect(result.stderr).toContain('svc has several fields, name one: username, password, PIN')
})
it('preserves field types during merges and accepts explicit types', async () => {
  expect(
    await cli(['set', 'tv://typed', '--stdin-json'], JSON.stringify({ custom: { type: 'text', value: 'first' } })),
  ).toMatchObject({ code: 0 })
  expect(await cli(['set', 'tv://typed', '--stdin'], 'second')).toMatchObject({ code: 0 })
  const result = await cli(['get', 'tv://typed', '--json'])
  expect(JSON.parse(result.stdout)).toEqual({ custom: { type: 'text', value: 'second' } })
})
it('writes arbitrary argv fields as text', async () => {
  expect(await cli(['set', 'tv://text', '--field', 'label=public'])).toMatchObject({ code: 0 })
  expect(await cli(['get', 'tv://text#label'])).toMatchObject({ code: 0, stdout: 'public\n' })
})
it.each([
  ['an existing secret field', ['tv://svc', '--field', 'password=leaked']],
  ["a preset's secret field", ['tv://login', '--preset', 'password', '--field', 'password=leaked']],
])('refuses %s as an argument', async (_, args) => {
  const result = await cli(['set', ...args, '--no-web'])
  expect(result.code).toBe(1)
  expect(result.stderr).toContain('pass "password" on stdin')
})
it('refuses --env for an entry with several fields and no default', async () => {
  const result = await cli(['set', 'tv://svc', '--env', 'SVC_TOKEN'])
  expect(result.code).toBe(1)
  expect(result.stderr).toContain('--env names the default field')
})
it('replaces expired OAuth credentials without refreshing them first', async () => {
  // given credentials past expiry whose token endpoint refuses connections
  const stale = {
    access_token: 'stale',
    refresh_token: 'revoked',
    expires_at: '2000-01-01T00:00:00.000Z',
    token_url: 'http://127.0.0.1:9/token',
  }
  expect(await cli(['set', 'tv://google', '--preset', 'oauth', '--stdin'], JSON.stringify(stale))).toMatchObject({
    code: 0,
  })

  // when they are replaced
  const replacement = JSON.stringify({ access_token: 'replacement' })
  const result = await cli(['set', 'tv://google', '--replace', '--preset', 'oauth', '--stdin'], replacement)

  // then the write succeeds and holds only the new token
  expect(result).toMatchObject({ code: 0 })
  expect(await cli(['get', 'tv://google', '--reveal'])).toMatchObject({ code: 0, stdout: 'replacement\n' })
})
it('rejects malformed OAuth stdin and accepts typed fields through stdin JSON', async () => {
  expect(await cli(['set', 'tv://oauth', '--preset', 'oauth', '--stdin'], 'token')).toMatchObject({ code: 1 })
  const fields = { session: { type: 'oauth', value: { access_token: 'access', refresh_token: 'refresh' } } }
  expect(await cli(['set', 'tv://oauth', '--stdin-json'], JSON.stringify(fields))).toMatchObject({ code: 0 })
  expect(await cli(['get', 'tv://oauth#session.refresh_token', '--reveal'])).toMatchObject({
    code: 0,
    stdout: 'refresh\n',
  })
})
