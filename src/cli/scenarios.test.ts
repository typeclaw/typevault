import { afterEach, beforeEach, expect, it } from 'bun:test'
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, parse } from 'node:path'

import { z } from 'zod'

import { isLockHeld } from '../core/lock'
import { LiveAccess } from '../daemon/live-access'

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

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
/** An actor's state directory for the shared checkout: where its daemon, grants and revision marks live. */
function runDir(name: string): string {
  const checkouts = join(base, name, 'typevault', 'checkouts')
  const [only] = readdirSync(checkouts)
  if (only === undefined) throw new Error(`${name} has no checkout state`)
  return join(checkouts, only, 'run')
}

/** A grants file in a format this version doesn't read, as an older release would leave it. */
const OLD_FORMAT_GRANTS = JSON.stringify([{ id: '4d74c52abdebdd72', label: 'old', groups: ['default'], only: [] }])

const secretKeyIn = (run: Run): string => /TVSK-[A-Z0-9-]+/.exec(run.stderr)?.[0] ?? ''

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

it(
  "an agent waits for the person to unlock, works through the session, and stops when it's locked",
  async () => {
    // given alice's vault with a secret
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(alice, ['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], 'sk-live-1')
    await ok(alice, ['lock'])

    // when her agent (no terminal) runs a command while the vault is locked, it is told to ask her
    const check = [
      'run',
      '--only',
      'typevault://openai',
      '--',
      process.execPath,
      '-e',
      'if (process.env.OPENAI === "sk-live-1") console.log("match")',
    ]
    expect(await fails(alice, check)).toContain('ask a human to run `typevault unlock`')

    // then once she unlocks, the agent's command gets the value and never prints it
    await ok(alice, withPassword('unlock'), line('a'))
    expect((await ok(alice, check)).stdout).toBe('match\n')
    expect(await fails(alice, ['get', 'typevault://openai'])).toContain('is secret')

    // and after she locks, it is refused again
    await ok(alice, ['lock'])
    expect(await fails(alice, check)).toContain('the vault is locked')
  },
  SCENARIO_MS,
)

it(
  'the owner session preserves its env override before and after rotation (#63)',
  async () => {
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(alice, ['set', 'custom', '--preset', 'api_key', '--env', 'MY_CUSTOM_KEY', '--stdin'], 'dummy-value')
    const token = (await ok(alice, ['grant', '--tier', 'default', '--label', 'agent:qa'])).stdout.trim()
    const agent = { ...alice, TYPEVAULT_GRANT: token }
    const check = [
      'run',
      '--only',
      'custom',
      '--',
      process.execPath,
      '-e',
      'console.log(JSON.stringify({ override: process.env.MY_CUSTOM_KEY === "dummy-value", derived: process.env.CUSTOM !== undefined }))',
    ]

    for (const caller of [alice, agent]) {
      expect(JSON.parse((await ok(caller, check)).stdout)).toEqual({ override: true, derived: false })
    }
    await ok(alice, withPassword('key', 'rotate', 'default'), line('a'))
    expect(JSON.parse((await ok(alice, check)).stdout)).toEqual({ override: true, derived: false })
  },
  SCENARIO_MS,
)

it.each(['live', 'sealed', 'derived'] as const)(
  'a lower %s writer cannot aim an env override at the owner or a higher grant',
  async (kind) => {
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('tier', 'add', 'trusted'), line('a'))
    await ok(alice, withPassword('tier', 'include', 'trusted', 'default'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    let token: string
    if (kind === 'derived') {
      const session = readFileSync(join(runDir('alice'), 'session.token'), 'utf8')
      const derived = await new LiveAccess(join(runDir('alice'), 'agent.sock'), session).call(
        '/v1/derive',
        { tiers: ['default'], label: 'agent:lower' },
        z.object({ token: z.string() }),
      )
      token = derived.token
    } else {
      token = (
        await ok(alice, [
          'grant',
          '--tier',
          'default',
          '--label',
          'agent:lower',
          ...(kind === 'sealed' ? ['--sealed'] : []),
        ])
      ).stdout.trim()
    }
    const lower = { ...alice, TYPEVAULT_GRANT: token }
    await ok(lower, ['set', 'custom', '--preset', 'api_key', '--env', 'MY_CUSTOM_KEY', '--stdin'], 'lower-value')
    const higher = {
      ...alice,
      TYPEVAULT_GRANT: (await ok(alice, ['grant', '--tier', 'trusted', '--label', 'agent:higher'])).stdout.trim(),
    }
    const check = [
      'run',
      '--only',
      'custom',
      '--',
      process.execPath,
      '-e',
      'console.log(JSON.stringify({ override: process.env.MY_CUSTOM_KEY !== undefined, derived: process.env.CUSTOM === "lower-value" }))',
    ]

    for (const caller of [alice, higher]) {
      expect(JSON.parse((await ok(caller, check)).stdout)).toEqual({ override: false, derived: true })
    }
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
    await ok(alice, ['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], 'sk-live-1')
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
    await ok(alice, ['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], 'sk-live-1')

    // when bob joins with his own password and alice adds him
    const joined = await ok(bob, withPassword('join', '--name', 'bob'), line('b'))
    await ok(alice, withPassword('member', 'add', 'bob', publicKeyIn(joined), '--tier', 'default'), line('a'))

    // then bob unlocks with his password, never alice's, and reads
    await fails(bob, withPassword('unlock'), line('a'))
    await ok(bob, withPassword('unlock'), line('b'))
    expect((await ok(bob, ['get', 'typevault://openai', '--reveal'])).stdout).toBe('sk-live-1\n')

    // and once removed, what he could read is flagged and he can't open anything written after
    const removed = await ok(alice, withPassword('member', 'rm', 'bob'), line('a'))
    expect(removed.stderr).toContain('openai')
    await ok(alice, ['set', 'typevault://stripe', '--preset', 'api_key', '--stdin'], 'sk-live-2')
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
    await ok(laptop, ['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], 'sk-live-1')

    // when a second device with only the checkout restores her identity
    const desktop = actor('desktop')
    await fails(desktop, withPassword('identity', 'restore', 'alice'), `TVSK-AAAAAAAA-AAAAAAAA-AAAAAAAA-AAAAAAAA\na\n`)
    await ok(desktop, withPassword('identity', 'restore', 'alice'), `${secretKeyIn(init)}\na\n`)

    // then it unlocks and reads like the first
    await ok(desktop, withPassword('unlock'), line('a'))
    expect((await ok(desktop, ['get', 'typevault://openai', '--reveal'])).stdout).toBe('sk-live-1\n')
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
    await ok(alice, ['set', 'typevault://openai', '--preset', 'api_key', '--tier', 'agents', '--stdin'], 'sk-agent-1')
    await ok(alice, ['set', 'typevault://stripe', '--preset', 'api_key', '--tier', 'default', '--stdin'], 'sk-live-2')

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

it(
  're-creating a vault in the same checkout starts clean, even with the old daemon running',
  async () => {
    // given a vault unlocked here, whose daemon is still running and whose state is from an older release
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(alice, ['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], 'sk-old')
    writeFileSync(join(runDir('alice'), 'grants.json'), OLD_FORMAT_GRANTS)

    // when the vault is deleted and created again in the same place
    rmSync(join(project, '.typevault'), { recursive: true })
    await ok(alice, withPassword('init'), '')

    // then the new vault unlocks and starts empty: none of the old runtime state is in the way
    await ok(alice, withPassword('unlock'), line('a'))
    expect(JSON.parse((await ok(alice, ['ls', '--json'])).stdout)).toEqual([])
  },
  SCENARIO_MS,
)

it(
  "a daemon that can't start says why",
  async () => {
    // given runtime state this release can't read, left in place
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    writeFileSync(join(runDir('alice'), 'grants.json'), OLD_FORMAT_GRANTS)

    // when the owner unlocks
    const error = await fails(alice, withPassword('unlock'), line('a'))

    // then the error identifies the broken state and where its full log is
    expect(error).toContain(join(runDir('alice'), 'grants.json'))
    expect(error).toContain(join(runDir('alice'), 'daemon.log'))
  },
  SCENARIO_MS,
)

/** Alice's vault, unlocked, holding one entry. */
async function unlockedVault(): Promise<Actor> {
  const alice = actor('alice')
  await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
  await ok(alice, withPassword('unlock'), line('a'))
  await ok(alice, ['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], 'sk-test')
  return alice
}

const issueGrant = async (alice: Actor): Promise<string> =>
  (await ok(alice, ['grant', '--tier', 'default', '--ttl', '1h', '--label', 'agent'])).stdout.trim()

it(
  "a daemon killed before its cleanup doesn't bring its session token back with the next unlock",
  async () => {
    // given an unlocked session whose daemon is killed, which leaves the grant live and the token on disk
    const alice = await unlockedVault()
    const run = runDir('alice')
    const token = readFileSync(join(run, 'session.token'), 'utf8').trim()
    process.kill(Number(readFileSync(join(run, 'daemon.pid'), 'utf8')), 'SIGKILL')
    while (isLockHeld(join(run, 'daemon.lock'))) await Bun.sleep(10)

    // when the vault is unlocked again
    await ok(alice, withPassword('unlock'), line('a'))

    // then the old token is refused
    expect(await fails({ ...alice, TYPEVAULT_GRANT: token }, ['ls'])).toContain('this grant was revoked')
  },
  SCENARIO_MS,
)

it(
  'an issued grant survives a daemon restart',
  async () => {
    // given a grant issued by a running session
    const alice = await unlockedVault()
    const token = await issueGrant(alice)

    // when the daemon stops and the vault is unlocked again
    await ok(alice, ['daemon', 'stop'])
    await ok(alice, withPassword('unlock'), line('a'))

    // then the grant still reads
    await ok({ ...alice, TYPEVAULT_GRANT: token }, ['ls'])
  },
  SCENARIO_MS,
)

it(
  'lock clears a grants file the daemon cannot read',
  async () => {
    // given runtime state this release can't read, which keeps the daemon from starting
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    writeFileSync(join(runDir('alice'), 'grants.json'), OLD_FORMAT_GRANTS)
    await fails(alice, withPassword('unlock'), line('a'))

    // when the owner locks
    await ok(alice, ['lock'])

    // then the next unlock starts
    await ok(alice, withPassword('unlock'), line('a'))
  },
  SCENARIO_MS,
)

it(
  "an issued grant doesn't come back after lock",
  async () => {
    // given a grant issued by a running session
    const alice = await unlockedVault()
    const token = await issueGrant(alice)

    // when the vault is locked and unlocked again
    await ok(alice, ['lock'])
    await ok(alice, withPassword('unlock'), line('a'))

    // then the grant is refused, and the lock is on the trail
    expect(await fails({ ...alice, TYPEVAULT_GRANT: token }, ['ls'])).toContain('unknown grant')
    const trail = (await ok(alice, ['audit'])).stdout
      .trim()
      .split('\n')
      .map((record): unknown => JSON.parse(record))
    expect(trail).toContainEqual(expect.objectContaining({ action: 'grant.revoke', reason: 'typevault lock' }))
  },
  SCENARIO_MS,
)

it(
  'audit --verify reports a damaged log as broken',
  async () => {
    // given a trail with a line that isn't a record
    const alice = await unlockedVault()
    const audit = join(dirname(runDir('alice')), 'audit')
    const [log] = readdirSync(audit)
    if (log === undefined) throw new Error('nothing was audited')
    appendFileSync(join(audit, log), 'garbage\n')

    // when it is verified
    const verified = await cli(alice, ['audit', '--verify'])

    // then the verdict says so, rather than the command crashing
    expect({ code: verified.code, broken: verified.stdout.startsWith('BROKEN') }).toEqual({ code: 1, broken: true })
  },
  SCENARIO_MS,
)

const badInputs: readonly (readonly [string, readonly string[], Actor, string])[] = [
  ['a non-numeric --if-rev', ['set', 'typevault://openai', 'note=x', '--if-rev', 'abc'], {}, '--if-rev'],
  ['a non-numeric prompt port', ['daemon', 'run'], { TYPEVAULT_PROMPT_PORT: 'abc' }, 'TYPEVAULT_PROMPT_PORT'],
]

for (const [what, args, extra, names] of badInputs) {
  it(
    `${what} fails with one line`,
    async () => {
      // given an unlocked vault
      const alice = await unlockedVault()

      // when the command runs with it
      const error = await fails({ ...alice, ...extra }, args)

      // then the error is a single line naming what was wrong
      expect(error.split('\n')).toEqual([expect.stringMatching(/^typevault: /), ''])
      expect(error).toContain(names)
    },
    SCENARIO_MS,
  )
}

it('stores OAuth JSON from stdin as the preset input field', async () => {
  const machine = actor('machine')
  await ok(machine, ['init', '--machine'])
  const credentials = { access_token: 'test-access-token', refresh_token: 'test-refresh-token' }

  await ok(machine, ['set', 'typevault://google', '--preset', 'oauth', '--stdin'], JSON.stringify(credentials))

  const stored = await ok(machine, ['get', 'typevault://google', '--json', '--reveal'])
  expect(JSON.parse(stored.stdout)).toEqual({ $default: { type: 'oauth', value: credentials } })
  expect((await ok(machine, ['get', 'typevault://google#refresh_token', '--reveal'])).stdout).toBe(
    'test-refresh-token\n',
  )
})
