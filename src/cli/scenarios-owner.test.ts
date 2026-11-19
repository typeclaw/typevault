import { expect, it } from 'bun:test'

import { actor, fails, line, ok, publicKeyIn, SCENARIO_MS, unlockedVault, withPassword } from './scenarios.harness'

it(
  'rotates the owner, cuts off the old session and sealed-grant writes, and lets the remaining owner unlock again',
  async () => {
    // given a session and both kinds of grants issued by this owner
    const alice = await unlockedVault()
    const bob = actor('bob')
    const joined = await ok(bob, ['join', '--name', 'bob', '--machine'])
    await ok(alice, withPassword('member', 'add', 'bob', publicKeyIn(joined), '--owner'), line('a'))
    const grant = ['grant', '--tier', 'default', '--ttl', '1h']
    const live = { ...alice, TYPEVAULT_GRANT: (await ok(alice, grant)).stdout.trim() }
    const sealed = { ...alice, TYPEVAULT_GRANT: (await ok(alice, [...grant, '--sealed'])).stdout.trim() }
    for (const caller of [live, sealed]) await ok(caller, ['get', 'openai', '--reveal'])

    // when Alice rotates away Bob's owner access
    const removed = await ok(alice, withPassword('member', 'rm', 'bob'), line('a'))
    expect(removed.stdout).toContain('removed bob')
    expect(removed.stderr).toMatch(/owner key rotated[\s\S]*pull/i)

    // then the old daemon refuses access, and the sealed grant can no longer write (its reads are a snapshot)
    await fails(live, ['ls'])
    await fails(sealed, ['set', 'new', '--preset', 'api_key', '--stdin'], 'new-value')
    await ok(alice, ['daemon', 'stop'])
    await ok(alice, withPassword('unlock'), line('a'))
    expect((await ok(alice, ['get', 'openai', '--reveal'])).stdout).toBe('sk-test\n')
    const fresh = { ...alice, TYPEVAULT_GRANT: (await ok(alice, grant)).stdout.trim() }
    expect((await ok(fresh, ['get', 'openai', '--reveal'])).stdout).toBe('sk-test\n')
  },
  SCENARIO_MS,
)
