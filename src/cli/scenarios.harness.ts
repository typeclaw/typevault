import { afterEach, beforeEach, expect } from 'bun:test'
import { mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
export const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

// End-to-end scenarios: every step runs the real CLI in its own process, as a person or an agent would. Each actor
// has its own config directory (its identity, trust pin and daemon), and they share one project checkout.

export const CLI = join(import.meta.dir, 'index.ts')
export const SCENARIO_MS = 30_000

export type Run = { readonly code: number; readonly stdout: string; readonly stderr: string }
export type Actor = Record<string, string>

export let base: string
export let project: string
export let actors: Actor[]

export async function cli(actor: Actor, args: readonly string[], stdin = ''): Promise<Run> {
  const proc = Bun.spawn([process.execPath, CLI, ...args], {
    cwd: project,
    env: actor,
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

export async function ok(actor: Actor, args: readonly string[], stdin = ''): Promise<Run> {
  const run = await cli(actor, args, stdin)
  expect({ args, code: run.code, stderr: run.code === 0 ? '' : run.stderr }).toEqual({ args, code: 0, stderr: '' })
  return run
}

export async function fails(actor: Actor, args: readonly string[], stdin = ''): Promise<string> {
  const run = await cli(actor, args, stdin)
  expect({ args, code: run.code }).toEqual({ args, code: 1 })
  return run.stderr
}

export function actor(name: string, extra: Actor = {}): Actor {
  const env = { PATH: process.env['PATH'] ?? '', XDG_CONFIG_HOME: join(base, name), ...extra }
  actors.push(env)
  return env
}

export const withPassword = (...args: string[]): string[] => [...args, '--vault-password-stdin']
export const line = (password: string): string => `${password}\n`
export const publicKeyIn = (run: Run): string => run.stdout.split(' ').find((word) => word.startsWith('tvp1:')) ?? ''
/** An actor's state directory for the shared checkout: where its daemon, grants and revision marks live. */
export function runDir(name: string): string {
  const checkouts = join(base, name, 'typevault', 'checkouts')
  const [only] = readdirSync(checkouts)
  if (only === undefined) throw new Error(`${name} has no checkout state`)
  return join(checkouts, only, 'run')
}

/** A grants file in a format this version doesn't read, as an older release would leave it. */
export const OLD_FORMAT_GRANTS = JSON.stringify([
  { id: '4d74c52abdebdd72', label: 'old', groups: ['default'], only: [] },
])

export const secretKeyIn = (run: Run): string => /TVSK-[A-Z0-9-]+/.exec(run.stderr)?.[0] ?? ''

beforeEach(() => {
  base = realpathSync(mkdtempSync(join(SHORT_TMP, 'tvs-')))
  project = join(base, 'p')
  mkdirSync(project)
  actors = []
})

afterEach(async () => {
  for (const env of actors) await cli(env, ['lock'])
  rmSync(base, { recursive: true, force: true })
})

export async function unlockedVault(): Promise<Actor> {
  const alice = actor('alice')
  await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
  await ok(alice, withPassword('unlock'), line('a'))
  await ok(alice, ['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], 'sk-test')
  return alice
}

export const issueGrant = async (alice: Actor): Promise<string> =>
  (await ok(alice, ['grant', '--tier', 'default', '--ttl', '1h', '--label', 'agent'])).stdout.trim()
