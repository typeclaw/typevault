import { expect, it } from 'bun:test'
import { appendFileSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { anchorAudit, appendAudit } from '../audit/log'
import { createIdentity, encodeMemberPublic, memberPublicOfIdentity } from '../core/identity'
import { localLayout } from '../core/layout'
import { ownerDoc, readOwner } from '../core/owner-trust'
import {
  type Actor,
  actor,
  base,
  cli,
  fails,
  issueGrant,
  line,
  ok,
  project,
  runDir,
  SCENARIO_MS,
  unlockedVault,
  withPassword,
} from './scenarios.harness'

it.each([
  ['audit --verify', ['audit', '--verify'], {}],
  ['the TYPEVAULT_OWNER check', ['ls'], { TYPEVAULT_GRANT: 'tvl1.test.test' }],
] as const)(
  '%s leaves a journal alone while another machine holds the state directory',
  async (_, args, extra) => {
    // given another machine's daemon claim and a transaction it has staged but not committed
    const alice = actor('alice')
    await ok(alice, ['init', '--name', 'alice', '--machine'])
    const layout = localLayout(join(project, '.typevault'), alice)
    const pin = { ...alice, ...extra, TYPEVAULT_OWNER: readOwner(layout).signPublic }
    const claim = { host: 'other-host', name: 'other', pid: 1, token: 'x', at: new Date().toISOString() }
    writeFileSync(layout.daemonHolder, JSON.stringify(claim))
    const staged = join(layout.txnDir, 'theirs')
    mkdirSync(staged, { recursive: true })

    // when this machine runs the command
    const result = await cli(pin, [...args])

    // then it refuses before recovery could discard their staging
    expect(result.code).not.toBe(0)
    expect(result.stderr).toContain('another machine')
    expect(existsSync(staged)).toBe(true)
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

it.each(['original', 'rotated', 'stripped'] as const)(
  'audit --verify rejects a missing anchored state-directory log with the %s owner history',
  async (history) => {
    // given an anchored log in a state directory and, where applicable, a trusted owner rotation
    const alice = actor('alice', { TYPEVAULT_STATE_DIR: join(base, 'state') })
    await ok(alice, ['init', '--name', 'alice', '--machine'])
    const layout = localLayout(join(project, '.typevault'), alice)
    await appendAudit(layout, { action: 'read', mode: 'direct', entries: ['openai'] })
    await anchorAudit(layout)
    if (history !== 'original') {
      const { identity } = await createIdentity('bob', 'machine')
      const key = encodeMemberPublic(memberPublicOfIdentity(identity))
      await ok(alice, ['member', 'add', 'bob', key, '--owner'])
      await ok(alice, ['member', 'rm', 'bob'])
    }
    await ok(alice, ['audit', '--verify'])
    if (history === 'stripped') {
      const { recipient, signPublic } = readOwner(layout)
      writeFileSync(layout.ownerFile, ownerDoc({ recipient, signPublic }))
    }
    rmSync(layout.auditLog)

    // when it is verified
    const verified = await cli(alice, ['audit', '--verify'])

    // then the anchored log is broken, or its altered owner history is refused before checking the log
    expect(verified.code).toBe(1)
    if (history === 'stripped') expect(verified.stderr).toContain('handovers')
    else expect(verified.stdout).toMatch(/^BROKEN: .*anchor/)
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

it(
  'ls says when an entry file is left out, without touching its JSON',
  async () => {
    // given an unlocked vault whose only entry file is damaged
    const alice = await unlockedVault()
    const entries = join(project, '.typevault', 'entries')
    const [file] = readdirSync(entries)
    if (file === undefined) throw new Error('the entry was not stored')
    writeFileSync(join(entries, file), '{not json')

    // when it is listed
    const listed = await ok(alice, ['ls', '--json'])

    // then stdout is still the (empty) list, and stderr counts what is missing from it
    expect(JSON.parse(listed.stdout)).toEqual([])
    expect(listed.stderr).toContain('1 entry file(s)')
  },
  SCENARIO_MS,
)

it(
  'refuses a live grant through a daemon from an older release',
  async () => {
    // given a daemon still running from before an upgrade: it answers pings without a version
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    const older = Bun.serve({
      unix: join(runDir('alice'), 'agent.sock'),
      fetch: (request) => {
        const path = new URL(request.url).pathname
        if (path === '/v1/ping') return Response.json({ ok: true, pid: process.pid })
        if (path === '/v1/list') return Response.json([])
        return Response.json({ error: { code: 'not_found', message: 'no such route' } }, { status: 404 })
      },
    })

    // when a grant without a machine key lists through it
    const listed = await cli({ ...alice, TYPEVAULT_GRANT: 'tvl1.id.secret' }, ['ls', '--json']).finally(() =>
      older.stop(true),
    )

    // then nothing is read through it, and stderr says how to replace it
    expect({ code: listed.code, stdout: listed.stdout }).toEqual({ code: 1, stdout: '' })
    expect(listed.stderr).toContain('daemon is from an older release')
    expect(listed.stderr).toContain('typevault daemon stop')
  },
  SCENARIO_MS,
)

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

it(
  'a grant limited with --only reaches only the entries it names',
  async () => {
    // given a vault holding a GitHub login and an OpenAI key
    const alice = await unlockedVault()
    await ok(alice, ['set', 'typevault://github/bot', '--preset', 'api_key', '--stdin'], 'ghp-test')

    // when an agent holds a grant for typevault://github/* only
    const token = (
      await ok(alice, ['grant', '--tier', 'default', '--only', 'typevault://github/*', '--label', 'ci:deploy'])
    ).stdout.trim()
    const agent = { ...alice, TYPEVAULT_GRANT: token }

    // then it lists and loads only the GitHub entry
    expect(JSON.parse((await ok(agent, ['ls', '--json'])).stdout)).toMatchObject([{ name: 'github/bot' }])
    const check = [
      'run',
      '--',
      process.execPath,
      '-e',
      'console.log(JSON.stringify({ github: process.env.GITHUB_BOT === "ghp-test", openai: process.env.OPENAI !== undefined }))',
    ]
    expect(JSON.parse((await ok(agent, check)).stdout)).toEqual({ github: true, openai: false })
    expect(await fails(agent, ['get', 'typevault://openai', '--reveal'])).toContain('no entry named openai')
  },
  SCENARIO_MS,
)

it(
  'a revoked grant stops reading while the session stays unlocked',
  async () => {
    // given an agent reading through a live grant
    const alice = await unlockedVault()
    const agent = { ...alice, TYPEVAULT_GRANT: await issueGrant(alice) }
    await ok(agent, ['ls'])

    // when the owner revokes it by label
    expect((await ok(alice, ['grant', 'revoke', '--label', 'agent'])).stdout).toBe('revoked 1 grant(s)\n')

    // then the agent is refused, and the owner still reads
    await fails(agent, ['ls'])
    expect(JSON.parse((await ok(alice, ['ls', '--json'])).stdout)).toMatchObject([{ name: 'openai' }])
  },
  SCENARIO_MS,
)

it(
  'a sealed grant in a file reads with the vault locked and no daemon running',
  async () => {
    // given a sealed grant written to a file
    const alice = await unlockedVault()
    const sealed = (await ok(alice, ['grant', '--tier', 'default', '--sealed', '--label', 'ci:build'])).stdout.trim()
    expect(sealed.startsWith('tvg1:')).toBe(true)
    const grantFile = join(base, 'build.grant')
    writeFileSync(grantFile, sealed, { mode: 0o600 })

    // when the vault is locked, which stops its daemon
    await ok(alice, ['lock'])
    await fails(alice, ['daemon', 'stop'])

    // then CI still runs with the secret
    const ci = { ...alice, TYPEVAULT_GRANT: `@${grantFile}` }
    const check = ['run', '--', process.execPath, '-e', 'if (process.env.OPENAI === "sk-test") console.log("match")']
    expect((await ok(ci, check)).stdout).toBe('match\n')
  },
  SCENARIO_MS,
)
