import { expect, it } from 'bun:test'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  actor,
  actors,
  base,
  fails,
  issueGrant,
  line,
  ok,
  project,
  SCENARIO_MS,
  publicKeyIn,
  unlockedVault,
  withPassword,
} from './scenarios.harness'

it(
  'run redacts a secret the child prints, on stdout and stderr',
  async () => {
    // given an agent holding a grant
    const alice = await unlockedVault()
    const agent = { ...alice, TYPEVAULT_GRANT: await issueGrant(alice) }

    // when its command prints the secret on both streams
    const leaky = await ok(agent, [
      'run',
      '--',
      process.execPath,
      '-e',
      'console.log("key=" + process.env.OPENAI); console.error("key=" + process.env.OPENAI)',
    ])

    // then neither stream carries the value
    expect({ stdout: leaky.stdout, stderr: leaky.stderr }).toEqual({
      stdout: 'key=[redacted]\n',
      stderr: 'key=[redacted]\n',
    })
  },
  SCENARIO_MS,
)

it(
  'redact scrubs piped output of the secrets a grant has read',
  async () => {
    // given an agent whose grant has read the secret
    const alice = await unlockedVault()
    const agent = { ...alice, TYPEVAULT_GRANT: await issueGrant(alice) }
    await ok(agent, ['run', '--', process.execPath, '-e', ''])

    // when output containing it is piped through redact
    const redacted = await ok(agent, ['redact'], 'Authorization: Bearer sk-test\n')

    // then the value is replaced
    expect(redacted.stdout).toBe('Authorization: Bearer [redacted]\n')
  },
  SCENARIO_MS,
)

it(
  'a renamed entry reads under its new name, and a removed one is gone',
  async () => {
    // given an entry
    const alice = await unlockedVault()

    // when it is renamed
    await ok(alice, ['mv', 'typevault://openai', 'typevault://openai/prod'])

    // then only the new name reads
    expect((await ok(alice, ['get', 'typevault://openai/prod', '--reveal'])).stdout).toBe('sk-test\n')
    await fails(alice, ['get', 'typevault://openai', '--reveal'])

    // and once removed, nothing is left
    await ok(alice, ['rm', 'typevault://openai/prod'])
    expect(JSON.parse((await ok(alice, ['ls', '--json'])).stdout)).toEqual([])
  },
  SCENARIO_MS,
)

it(
  '--if-rev refuses a write based on a revision someone else already replaced',
  async () => {
    // given an entry at r1
    const alice = await unlockedVault()

    // when one writer updates it from r1
    await ok(alice, ['set', 'typevault://openai', '--field', 'note=first', '--if-rev', '1'])

    // then a second writer still holding r1 is refused, and the first write stands
    await fails(alice, ['set', 'typevault://openai', '--field', 'note=second', '--if-rev', '1'])
    expect((await ok(alice, ['get', 'typevault://openai#note'])).stdout).toBe('first\n')
  },
  SCENARIO_MS,
)

it(
  "a member sees only their tiers, not the owner's other ones",
  async () => {
    // given alice's vault with a key in default and one in an ops tier
    const alice = actor('alice')
    const bob = actor('bob')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('tier', 'add', 'ops'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(alice, ['set', 'typevault://openai', '--preset', 'api_key', '--tier', 'default', '--stdin'], 'sk-test')
    await ok(alice, ['set', 'typevault://stripe', '--preset', 'api_key', '--tier', 'ops', '--stdin'], 'sk-ops')

    // when bob joins the default tier only
    const joined = await ok(bob, withPassword('join', '--name', 'bob'), line('b'))
    await ok(alice, withPassword('member', 'add', 'bob', publicKeyIn(joined), '--tier', 'default'), line('a'))
    await ok(bob, withPassword('unlock'), line('b'))

    // then he lists and reads the default entry, and the ops one is out of reach
    expect(JSON.parse((await ok(bob, ['ls', '--json'])).stdout)).toMatchObject([{ name: 'openai' }])
    await fails(bob, ['get', 'typevault://stripe', '--reveal'])
  },
  SCENARIO_MS,
)

it(
  'an imported .env reaches a command under its own variable names',
  async () => {
    // given an unlocked vault and a dotenv file (not named .env: Bun would load that into the child itself)
    const alice = actor('alice')
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    writeFileSync(join(project, 'import.env'), 'STRIPE_KEY=sk-dotenv\n')

    // when it is imported
    await ok(alice, withPassword('import', 'dotenv', 'import.env', '--tier', 'default'), line('a'))

    // then an agent's command gets the value under the same name
    const agent = { ...alice, TYPEVAULT_GRANT: await issueGrant(alice) }
    const check = [
      'run',
      '--',
      process.execPath,
      '-e',
      'if (process.env.STRIPE_KEY === "sk-dotenv") console.log("match")',
    ]
    expect((await ok(agent, check)).stdout).toBe('match\n')
  },
  SCENARIO_MS,
)

it(
  'an env var set to a reference picks the name the secret arrives under',
  async () => {
    // given an agent holding a grant
    const alice = await unlockedVault()
    const agent = { ...alice, TYPEVAULT_GRANT: await issueGrant(alice), API_TOKEN: 'typevault://openai' }

    // when it runs a command with API_TOKEN pointing at the entry
    const check = ['run', '--', process.execPath, '-e', 'if (process.env.API_TOKEN === "sk-test") console.log("match")']

    // then the command sees the secret under that name
    expect((await ok(agent, check)).stdout).toBe('match\n')
  },
  SCENARIO_MS,
)

it(
  'a name missing from the project vault points at the global vault only while an unlocked global session has it',
  async () => {
    // given a project vault, and a global vault holding openai, both unlocked
    const alice = actor('alice', { HOME: join(base, 'home') })
    const global = { ...alice, TYPEVAULT_GLOBAL: '1' }
    actors.push(global)
    await ok(alice, withPassword('init', '--name', 'alice'), line('a'))
    await ok(global, withPassword('init', '--name', 'alice'), line('a'))
    await ok(alice, withPassword('unlock'), line('a'))
    await ok(global, withPassword('unlock'), line('a'))
    await ok(global, ['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], 'sk-global')

    // when the project vault is asked for it, the miss names the global vault
    expect(await fails(alice, ['get', 'typevault://openai'])).toContain('the global vault has it: rerun with -g')
    expect((await ok(alice, ['run', '--only', 'typevault://openai', '--', 'true'])).stderr).toContain(
      'the global vault has openai: rerun with -g',
    )

    // then a name the global vault lacks, or a locked global vault, says nothing about it
    expect(await fails(alice, ['get', 'typevault://stripe'])).not.toContain('global')
    await ok(global, ['lock'])
    expect(await fails(alice, ['get', 'typevault://openai'])).not.toContain('global')
  },
  SCENARIO_MS,
)
