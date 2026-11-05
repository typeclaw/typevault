import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { localLayout } from '../core/layout'

const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
const CLI = join(import.meta.dir, 'index.ts')
let root: string
let project: string
let env: Record<string, string>

async function cli(args: readonly string[]) {
  const proc = Bun.spawn([process.execPath, CLI, ...args], {
    cwd: project,
    env,
    stdin: 'ignore',
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

beforeEach(() => {
  mkdirSync(SHORT_TMP, { recursive: true })
  root = realpathSync(mkdtempSync(join(SHORT_TMP, 'tv-errors-')))
  project = join(root, 'project')
  mkdirSync(project)
  env = { PATH: process.env['PATH'] ?? '', HOME: join(root, 'home'), XDG_CONFIG_HOME: join(root, 'config') }
})
afterEach(async () => {
  await cli(['lock'])
  rmSync(root, { recursive: true, force: true })
})

it('reports an absent audit log in one line when following a fresh vault', async () => {
  expect((await cli(['init', '--machine'])).code).toBe(0)
  const result = await cli(['audit', '--follow'])

  expect(result.code).toBe(1)
  expect(result.stderr.trim().split('\n')).toHaveLength(1)
  expect(result.stderr).toStartWith('typevault: ')
  expect(result.stderr).toContain(localLayout(join(project, '.typevault'), env).auditLog)
})

it('reports corrupt runtime grants to doctor', async () => {
  expect((await cli(['init', '--machine'])).code).toBe(0)
  const layout = localLayout(join(project, '.typevault'), env)
  writeFileSync(layout.grantsFile, '')

  const result = await cli(['doctor'])

  expect(result.code).toBe(1)
  expect(result.stderr).toContain(layout.grantsFile)
})

it('reports filesystem initialization failure in one line', async () => {
  expect((await cli(['init', '--machine'])).code).toBe(0)
  rmSync(join(project, '.typevault'), { recursive: true })
  writeFileSync(join(project, '.typevault'), '')

  const result = await cli(['init', '--machine'])

  expect(result.code).toBe(1)
  expect(result.stderr.trim().split('\n')).toHaveLength(1)
  expect(result.stderr).toStartWith('typevault: ')
  expect(result.stderr).toContain('.typevault')
})
