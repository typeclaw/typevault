import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { join } from 'node:path'

// End-to-end scenarios: every step runs the real CLI in its own process, as a person or an agent would. Each actor
// has its own config directory (its identity, trust pin and daemon), and they share one project checkout.

const CLI = join(import.meta.dir, 'index.ts')
const SCENARIO_MS = 30_000

type Run = { readonly code: number; readonly stdout: string; readonly stderr: string }
type Actor = Record<string, string>

let base: string
let project: string
let actors: Actor[]

async function cli(actor: Actor, args: readonly string[], stdin = ''): Promise<Run> {
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

async function ok(actor: Actor, args: readonly string[], stdin = ''): Promise<Run> {
  const run = await cli(actor, args, stdin)
  expect({ args, code: run.code, stderr: run.code === 0 ? '' : run.stderr }).toEqual({ args, code: 0, stderr: '' })
  return run
}

async function fails(actor: Actor, args: readonly string[], stdin = ''): Promise<string> {
  const run = await cli(actor, args, stdin)
  expect({ args, code: run.code }).toEqual({ args, code: 1 })
  return run.stderr
}

function actor(name: string, extra: Actor = {}): Actor {
  const env = { PATH: process.env['PATH'] ?? '', XDG_CONFIG_HOME: join(base, name), ...extra }
  actors.push(env)
  return env
}

const withPassword = (...args: string[]): string[] => [...args, '--vault-password-stdin']
const line = (password: string): string => `${password}\n`
const publicKeyIn = (run: Run): string => run.stdout.split(' ').find((word) => word.startsWith('tvp1:')) ?? ''
const secretKeyIn = (run: Run): string => /TVSK-[A-Z0-9-]+/.exec(run.stderr)?.[0] ?? ''

beforeEach(() => {
  // Short root: the daemon's unix socket path is limited to ~104 bytes.
  base = realpathSync(mkdtempSync('/tmp/tvs-'))
  project = join(base, 'p')
  mkdirSync(project)
  actors = []
})

afterEach(async () => {
  for (const env of actors) await cli(env, ['lock'])
  rmSync(base, { recursive: true, force: true })
})

it(
  "an agent waits for the person to unlock, works through the session, and stops when it's locked",
  async () => {
    // given alice's vault with a secret
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(alice, ['set', 'tv://openai', '--type', 'api_key', '--stdin'], 'sk-live-1')
    await ok(alice, ['lock'])

    // when her agent (no terminal) runs a command while the vault is locked, it is told to ask her
    const check = ['run', '--only', 'tv://openai', '--', 'sh', '-c', 'test "$OPENAI_KEY" = sk-live-1 && echo match']
    expect(await fails(alice, check)).toContain('ask a human to run `typevault unlock`')

    // then once she unlocks, the agent's command gets the value and never prints it
    await ok(alice, withPassword('unlock'), line('a'))
    expect((await ok(alice, check)).stdout).toBe('match\n')
    expect(await fails(alice, ['get', 'tv://openai'])).toContain('is secret')

    // and after she locks, it is refused again
    await ok(alice, ['lock'])
    expect(await fails(alice, check)).toContain('the vault is locked')
  },
  SCENARIO_MS,
)

it(
  'a live grant issued in an unlocked session dies with the session',
  async () => {
    // given an unlocked vault and a grant for an agent
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(alice, ['set', 'tv://openai', '--type', 'api_key', '--stdin'], 'sk-live-1')
    const token = (await ok(alice, ['grant', '--tier', 'default', '--label', 'agent:a'])).stdout.trim()
    const agent = { ...alice, TYPEVAULT_GRANT: token }

    // then the agent reads through it
    expect(JSON.parse((await ok(agent, ['ls', '--json'])).stdout)).toMatchObject([{ name: 'openai' }])

    // and when the session is locked, the grant can't reach the vault until a person unlocks again
    await ok(alice, ['lock'])
    expect(await fails(agent, ['ls'])).toContain('the vault is locked')
  },
  SCENARIO_MS,
)

it(
  'a collaborator joins with their own password, reads, and is cut off from new secrets once removed',
  async () => {
    // given alice's vault with a secret
    const alice = actor('alice')
    const bob = actor('bob')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(alice, ['set', 'tv://openai', '--type', 'api_key', '--stdin'], 'sk-live-1')

    // when bob joins with his own password and alice adds him
    const joined = await ok(bob, withPassword('join', '--name', 'bob'), line('b'))
    await ok(alice, withPassword('member', 'add', 'bob', publicKeyIn(joined), '--tier', 'default'), line('a'))

    // then bob unlocks with his password, never alice's, and reads
    await fails(bob, withPassword('unlock'), line('a'))
    await ok(bob, withPassword('unlock'), line('b'))
    expect((await ok(bob, ['get', 'tv://openai', '--reveal'])).stdout).toBe('sk-live-1\n')

    // and once removed, what he could read is flagged and he can't open anything written after
    const removed = await ok(alice, withPassword('member', 'rm', 'bob'), line('a'))
    expect(removed.stderr).toContain('openai')
    await ok(alice, ['set', 'tv://stripe', '--type', 'api_key', '--stdin'], 'sk-live-2')
    expect(JSON.parse((await ok(bob, ['ls', '--json'])).stdout)).toEqual([])
  },
  SCENARIO_MS,
)

it(
  'a new device gets back in with the Secret Key and password alone',
  async () => {
    // given alice's vault on her first device
    const laptop = actor('laptop')
    const init = await ok(laptop, withPassword('init', '--name', 'alice'), line('a'))
    await ok(laptop, withPassword('unlock'), line('a'))
    await ok(laptop, ['set', 'tv://openai', '--type', 'api_key', '--stdin'], 'sk-live-1')

    // when a second device with only the checkout restores her identity
    const desktop = actor('desktop')
    await fails(desktop, withPassword('identity', 'restore', 'alice'), `TVSK-AAAAAAAA-AAAAAAAA-AAAAAAAA-AAAAAAAA\na\n`)
    await ok(desktop, withPassword('identity', 'restore', 'alice'), `${secretKeyIn(init)}\na\n`)

    // then it unlocks and reads like the first
    await ok(desktop, withPassword('unlock'), line('a'))
    expect((await ok(desktop, ['get', 'tv://openai', '--reveal'])).stdout).toBe('sk-live-1\n')
  },
  SCENARIO_MS,
)

it(
  'a changed password unlocks, and the old one stops working',
  async () => {
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))

    await ok(alice, withPassword('passwd'), 'a\nnew password\n')

    expect(await fails(alice, withPassword('unlock'), line('a'))).toContain('wrong password')
    await ok(alice, withPassword('unlock'), line('new password'))
  },
  SCENARIO_MS,
)

it(
  'an agent host (a machine member) issues grants to its sessions unattended, within its ceiling',
  async () => {
    // given alice's vault with a tier for agents, and a ceiling for the host's socket
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('tier', 'add', 'agents'), line('a'))
    await ok(alice, withPassword('ceiling', 'set', 'host', 'agents'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(alice, ['set', 'tv://openai', '--type', 'api_key', '--tier', 'agents', '--stdin'], 'sk-agent-1')
    await ok(alice, ['set', 'tv://stripe', '--type', 'api_key', '--tier', 'default', '--stdin'], 'sk-live-2')

    // when a host joins as a machine and alice adds it to the agents tier
    const host = actor('host', { TYPEVAULT_CEILING: 'host' })
    const joined = await ok(host, ['join', '--machine', '--name', 'host'])
    await ok(alice, withPassword('member', 'add', 'host', publicKeyIn(joined), '--tier', 'agents'), line('a'))

    // then, with no person around, the host mints a grant and its session reads only the agents tier
    const token = (await ok(host, ['grant', '--tier', 'agents', '--label', 'session:1'])).stdout.trim()
    const session = { ...host, TYPEVAULT_GRANT: token }
    expect(JSON.parse((await ok(session, ['ls', '--json'])).stdout)).toMatchObject([{ name: 'openai' }])
    expect(await fails(host, ['grant', '--tier', 'default'])).toContain('above this socket')
    const identity = JSON.parse(readFileSync(join(base, 'host', 'typevault', 'identity.json'), 'utf8'))
    expect(identity).toMatchObject({ kind: 'machine', name: 'host' })
  },
  SCENARIO_MS,
)
