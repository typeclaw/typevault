import { expect, it } from 'bun:test'
import { existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { localLayout } from '../../core/layout'
import { PACKAGE_VERSION } from '../../core/version'
import { servingPid, servingVersion } from '../../daemon/client'
import { base, cli, otherReleaseDaemon, owner, PASSWORD, project, succeeds } from './admin.harness'

it.each([
  [
    'does not narrow from separate child arguments',
    ['--only', 'typevault://stripe'],
    ['run', '--only', 'typevault://openai'],
    '1,0',
  ],
  ['does not widen from an equals child argument', ['--only=typevault://stripe'], ['run'], '0,0'],
])('%s', async (_, childArgs, runArgs, expected) => {
  succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  succeeds(await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  succeeds(await cli(['set', 'typevault://stripe', '--preset', 'api_key', '--stdin'], owner, 'sk-test-2'))
  const child = join(base, 'only-child.ts')
  writeFileSync(
    child,
    "console.log([process.env.OPENAI === undefined ? 0 : 1, process.env.STRIPE === undefined ? 0 : 1].join(','))",
  )

  const result = succeeds(await cli([...runArgs, '--', process.execPath, child, ...childArgs], owner))

  expect(result.stdout).toBe(`${expected}\n`)
})

it('returns the shell status for a missing command without a stack', async () => {
  succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  const result = await cli(['run', '--', 'definitely-not-a-command'], owner)
  expect(result.code).toBe(127)
  expect(result.stderr.trim().split('\n')).toHaveLength(1)
})

it.skipIf(process.platform === 'win32')(
  'returns the shell status for a not executable command without a stack',
  async () => {
    succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
    const executable = join(base, 'not-executable')
    writeFileSync(executable, '#!/bin/sh\nexit 0\n', { mode: 0o600 })
    const result = await cli(['run', '--', executable], owner)
    expect(result.code).toBe(126)
    expect(result.stderr.trim().split('\n')).toHaveLength(1)
  },
)

it.each([
  [
    'the sealed copy',
    (vault: string, outside: string) => {
      rmSync(join(vault, 'members', 'alice.key'))
      symlinkSync(outside, join(vault, 'members', 'alice.key'))
    },
  ],
  [
    'its directory',
    (vault: string, outside: string) => {
      const dir = join(base, 'elsewhere')
      mkdirSync(dir)
      symlinkSync(outside, join(dir, 'alice.key'))
      rmSync(join(vault, 'members'), { recursive: true })
      symlinkSync(dir, join(vault, 'members'))
    },
  ],
])('refuses to unlock through a symlinked %s, leaving the target untouched', async (_, plant) => {
  // given the committed sealed copy redirected to a file outside the vault, and a password change to sync
  const outside = join(base, 'outside.txt')
  writeFileSync(outside, 'keep me')
  succeeds(await cli(['passwd', '--vault-password-stdin'], owner, `${PASSWORD}\nnew password\n`))
  const vault = join(project, '.typevault')
  plant(vault, outside)

  // when the owner unlocks
  const run = await cli(['unlock', '--vault-password-stdin'], owner, 'new password\n')

  // then it is refused and the outside file keeps its content
  expect({ code: run.code, refused: run.stderr.includes('is a symlink') }).toEqual({ code: 1, refused: true })
  expect(readFileSync(outside, 'utf8')).toBe('keep me')
})

/** Adds a machine member, `ci`, and a ceiling its daemon can serve. Returns its key. */
async function addMachineMember(): Promise<string> {
  const machine = { PATH: owner['PATH'] ?? '', XDG_CONFIG_HOME: join(base, 'ci') }
  const joined = succeeds(await cli(['join', '--machine', '--name', 'ci'], machine))
  const publicKey = joined.stdout.split(' ').find((word) => word.startsWith('tvp1:')) ?? ''
  succeeds(
    await cli(
      ['member', 'add', 'ci', publicKey, '--tier', 'default', '--vault-password-stdin'],
      owner,
      `${PASSWORD}\n`,
    ),
  )
  succeeds(await cli(['ceiling', 'set', 'bot', 'default', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  return JSON.parse(readFileSync(join(base, 'ci', 'typevault', 'identity.json'), 'utf8')).key
}

it('replaces a machine daemon from another release with this one', async () => {
  // given a machine member, and a daemon from another release serving this checkout
  const key = await addMachineMember()
  const layout = localLayout(join(project, '.typevault'), owner)
  const other = await otherReleaseDaemon(layout)

  // when the machine member uses the vault
  succeeds(await cli(['daemon', 'start'], { ...owner, TYPEVAULT_KEY: key }))

  // then that daemon stopped, and this release's serves instead
  expect(await other.exited).toBe(0)
  expect(await servingVersion(layout.agentSocket)).toBe(PACKAGE_VERSION)
}, 30_000)

it('restarts a machine daemon as a new process', async () => {
  // given a machine member's daemon serving this checkout
  const key = await addMachineMember()
  const machine = { ...owner, TYPEVAULT_KEY: key }
  const layout = localLayout(join(project, '.typevault'), owner)
  succeeds(await cli(['daemon', 'start'], machine))
  const before = await servingPid(layout.agentSocket)

  // when it is restarted
  succeeds(await cli(['daemon', 'restart'], machine))

  // then another process of this release serves instead
  const after = await servingPid(layout.agentSocket)
  expect({ running: after !== undefined, replaced: after !== before }).toEqual({ running: true, replaced: true })
  expect(await servingVersion(layout.agentSocket)).toBe(PACKAGE_VERSION)
}, 30_000)

it('restarts over a session token left by a killed daemon', async () => {
  // given a machine member, and an unlocked session whose daemon was killed before its cleanup
  const key = await addMachineMember()
  succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  const layout = localLayout(join(project, '.typevault'), owner)
  const pid = Number(readFileSync(join(layout.run, 'daemon.pid'), 'utf8'))
  process.kill(pid, 'SIGKILL')
  while (isProcessRunning(pid)) await Bun.sleep(10)

  // when the machine member restarts the daemon
  succeeds(await cli(['daemon', 'restart'], { ...owner, TYPEVAULT_KEY: key }))

  // then this release serves, and the stale token is gone
  expect(await servingVersion(layout.agentSocket)).toBe(PACKAGE_VERSION)
  expect(existsSync(layout.sessionFile)).toBe(false)
}, 30_000)

function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

it('refuses to restart an unlocked session, and leaves it running', async () => {
  // given an unlocked session
  succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  const layout = localLayout(join(project, '.typevault'), owner)
  const before = await servingPid(layout.agentSocket)

  // when the owner restarts the daemon
  const run = await cli(['daemon', 'restart'], owner)

  // then they are told how to replace it, and the session keeps serving
  expect({ code: run.code, stderr: run.stderr }).toEqual({
    code: 1,
    stderr:
      'typevault: this daemon holds an unlocked session, which a restart would end: ' +
      'run `typevault lock`, then `typevault unlock`\n',
  })
  expect(await servingPid(layout.agentSocket)).toBe(before)
}, 30_000)

it('refuses an unlocked session from another release, and leaves it running', async () => {
  // given a session daemon from another release serving this checkout
  const layout = localLayout(join(project, '.typevault'), owner)
  const other = await otherReleaseDaemon(layout)
  writeFileSync(layout.sessionFile, 'tvl1.from-another-release', { mode: 0o600 })

  // when the owner reads through it
  const run = await cli(['ls'], owner)

  // then they are told how to replace it, and the session keeps its key until they do
  expect({ code: run.code, stderr: run.stderr }).toEqual({
    code: 1,
    stderr:
      `typevault: the running typevault daemon is version 0.0.0-other, not ${PACKAGE_VERSION}: ` +
      'run `typevault lock`, then `typevault unlock`\n',
  })
  expect(other.exitCode).toBeNull()
})

it('replaces a daemon that holds no session when its owner unlocks', async () => {
  // given a daemon for this checkout that holds no session: here a machine member's, started without a password
  const key = await addMachineMember()
  succeeds(await cli(['daemon', 'start'], { ...owner, TYPEVAULT_KEY: key }))
  expect((await cli(['ls'], owner)).stderr).toContain('the vault is locked')

  // when the owner unlocks
  const unlocked = succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))

  // then the session replaced that daemon, and the owner's commands go through it
  expect(unlocked.stdout).toContain('unlocked vault')
  succeeds(await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  expect(JSON.parse(succeeds(await cli(['ls', '--json'], owner)).stdout)).toMatchObject([{ name: 'openai' }])
}, 30_000)
