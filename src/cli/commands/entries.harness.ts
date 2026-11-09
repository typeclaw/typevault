import { afterEach, beforeEach, expect } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { seal } from '../../core/crypto'

export const CLI = join(import.meta.dir, '..', 'index.ts')
// Low-entropy values: anything derived from them in the output would be brute-forceable.
export const PASSWORD = 'hunter2'
export const PIN = '123456'

export let base: string
export let project: string
export let env: Record<string, string>

export async function cli(args: readonly string[], stdin?: string) {
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

export type PageRun = { readonly code: number; readonly output: string; readonly prompted: boolean }

// Runs `set`, filling the one-time page with `fields` if it shows one (or killing the command when `fields` is absent).
export async function setViaPage(
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

export async function fillPage(url: string, name: string, fields: Record<string, string>): Promise<void> {
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

export function expectNothingDerivedFrom(output: string, secret: string): void {
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
  expect((await cli(['set', 'typevault://svc', '--preset', 'password', '--stdin-json'], fields)).code).toBe(0)
})
afterEach(() => rmSync(base, { recursive: true, force: true }))
