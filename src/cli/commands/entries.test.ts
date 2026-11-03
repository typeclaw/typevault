import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

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
  expect((await cli(['init'])).code).toBe(0)
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
