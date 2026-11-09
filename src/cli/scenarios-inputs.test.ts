import { expect, it } from 'bun:test'
import { appendFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

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
