import { expect, it } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { LiveAccess } from '../daemon/live-access'
import {
  actor,
  fails,
  line,
  ok,
  runDir,
  SCENARIO_MS,
  secretKeyIn,
  publicKeyIn,
  withPassword,
} from './scenarios.harness'

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

    // then the agent reads through it, field names included
    expect(JSON.parse((await ok(agent, ['ls', '--json'])).stdout)).toMatchObject([
      { name: 'openai', fieldNames: ['$default'] },
    ])
    expect((await ok(agent, ['ls'])).stdout).toMatch(/FIELDS[\s\S]*openai .*\$default/)

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
