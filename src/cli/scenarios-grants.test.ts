import { expect, it } from 'bun:test'
import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { isLockHeld } from '../core/lock'
import {
  actor,
  base,
  fails,
  issueGrant,
  line,
  ok,
  OLD_FORMAT_GRANTS,
  project,
  runDir,
  SCENARIO_MS,
  publicKeyIn,
  unlockedVault,
  withPassword,
} from './scenarios.harness'

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
