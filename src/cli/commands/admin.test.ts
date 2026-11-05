import { afterEach, beforeEach, expect, it, setSystemTime } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { issueSealedGrant, readSealedGrant, sealedSigningSecret } from '../../access/sealed'
import { Admin } from '../../core/admin'
import { createIdentity, writeIdentity } from '../../core/identity'
import { founderOf, initGlobalVault } from '../../core/init'
import { globalLayout } from '../../core/layout'
import { parseEntryName } from '../../core/naming'
import { Vault } from '../../core/vault'

const envIn = (dir: string) => ({ TYPEVAULT_DIR: join(dir, 'vault'), XDG_CONFIG_HOME: dir })

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

const CLI = join(import.meta.dir, '..', 'index.ts')
const PASSWORD = 'correct horse battery staple'

type Run = { readonly code: number; readonly stdout: string; readonly stderr: string }

let base: string
let project: string
let owner: Record<string, string>

async function cli(args: readonly string[], env: Record<string, string>, stdin = ''): Promise<Run> {
  const proc = Bun.spawn([process.execPath, CLI, ...args], {
    cwd: project,
    env,
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

const succeeds = (run: Run): Run => {
  expect({ code: run.code, stderr: run.code === 0 ? '' : run.stderr }).toEqual({ code: 0, stderr: '' })
  return run
}

beforeEach(async () => {
  base = realpathSync(mkdtempSync(join(SHORT_TMP, 'tvc-')))
  project = join(base, 'p')
  mkdirSync(project)
  owner = { PATH: process.env['PATH'] ?? '', XDG_CONFIG_HOME: join(base, 'alice') }
  const init = succeeds(await cli(['init', '--name', 'alice', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  expect(init.stderr).toContain('TVSK-')
})

afterEach(async () => {
  await cli(['lock'], owner)
  rmSync(base, { recursive: true, force: true })
})

it('keeps a human-owned vault locked until its owner unlocks it, and locks it again', async () => {
  // given a fresh vault: commands from a non-terminal (an agent) can't ask for the password
  const locked = await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1')
  expect({ code: locked.code, stderr: locked.stderr }).toEqual({
    code: 1,
    stderr: 'typevault: the vault is locked: ask a human to run `typevault unlock`\n',
  })

  // when the owner unlocks it
  succeeds(await cli(['unlock', '--for', '10m', '--vault-password-stdin'], owner, `${PASSWORD}\n`))

  // then commands go through the session until it is locked again
  succeeds(await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  expect(JSON.parse(succeeds(await cli(['ls', '--json'], owner)).stdout)).toMatchObject([{ name: 'openai' }])
  succeeds(await cli(['lock'], owner))
  expect((await cli(['ls'], owner)).stderr).toContain('the vault is locked')
})

it('keeps identity and checkout state directories private', () => {
  if (process.platform === 'win32') return
  const config = join(base, 'alice', 'typevault')
  const checkout = join(config, 'checkouts', readdirSync(join(config, 'checkouts'))[0] ?? '')
  expect(statSync(config).mode & 0o777).toBe(0o700)
  expect(statSync(checkout).mode & 0o777).toBe(0o700)
})

it('rejects a zero unlock duration before starting a daemon', async () => {
  const result = await cli(['unlock', '--for', '0s', '--vault-password-stdin'], owner, `${PASSWORD}\n`)
  expect(result).toMatchObject({ code: 1 })
  expect(result.stderr).not.toContain('daemon did not start')
})

it.each(['github/late', 'TYPEVAULT://GitHub/Late', 'typevault://github/late'])(
  'keeps an expired sealed write only when doctor --adopt-expired pins it (as %p)',
  async (named) => {
    // given a machine-owned vault holding a write from a sealed grant that expired an hour ago
    const root = join(base, 'm')
    const { identity } = await createIdentity('owner', 'machine')
    writeIdentity(envIn(root), identity)
    const vault = await Vault.open(
      globalLayout(envIn(root)),
      [(await initGlobalVault(founderOf(identity), envIn(root))).owner],
      {},
    )
    await new Admin(vault).addTier('member')
    setSystemTime(Date.now() - 3_600_000)
    try {
      const grant = { tiers: ['member'], only: [], ttlMs: 60_000, label: 'ci' }
      const bundle = await readSealedGrant(await issueSealedGrant(vault, grant))
      await vault.put(
        { name: parseEntryName('github/late'), fields: { key: { type: 'secret', value: 'x' } }, tier: 'member' },
        { ref: { kind: 'cert', cert: bundle.write.cert }, signSecret: sealedSigningSecret(bundle) },
      )
    } finally {
      setSystemTime()
    }
    const env = { PATH: owner['PATH'] ?? '', ...envIn(root) }

    // when the owner runs doctor --fix without pinning it, then by name alone, then with the digest it listed
    const skipped = await cli(['doctor', '--fix'], env)
    const nameOnly = await cli(['doctor', '--fix', '--adopt-expired', named], env)
    const digest = /--adopt-expired github\/late@([0-9a-f]{16})/.exec(skipped.stdout)?.[1]
    const adopted = succeeds(await cli(['doctor', '--fix', '--adopt-expired', `${named}@${digest}`], env))

    // then it is listed with its revision and left alone, a bare name is refused, then it is adopted
    expect(skipped.stdout).toContain('expired sealed write: github/late rev 1 at ')
    expect(nameOnly.stderr).toContain('--adopt-expired expects <name>@<digest>')
    expect(adopted.stdout).toContain('adopted sealed write: github/late')
  },
)

it('refuses to unlock with the wrong password', async () => {
  const run = await cli(['unlock', '--vault-password-stdin'], owner, 'wrong\n')

  expect({ code: run.code, stderr: run.stderr }).toEqual({
    code: 1,
    stderr: 'typevault: wrong password or Secret Key\n',
  })
})

it('lets a machine member that joined read its tier without any password', async () => {
  // given a secret in the default tier
  succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  succeeds(await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))

  // when a machine joins and the owner adds it with the line join printed
  const machine = { PATH: owner['PATH'] ?? '', XDG_CONFIG_HOME: join(base, 'ci') }
  const joined = succeeds(await cli(['join', '--machine', '--name', 'ci'], machine))
  const publicKey = joined.stdout.split(' ').find((word) => word.startsWith('tvp1:')) ?? ''
  const added = ['member', 'add', 'ci', publicKey, '--tier', 'default', '--vault-password-stdin']
  succeeds(await cli(added, owner, `${PASSWORD}\n`))

  // then the machine reads the secret directly
  const read = succeeds(await cli(['get', 'typevault://openai', '--reveal'], machine))
  expect(read.stdout).toBe('sk-test-1\n')
})

it('bulk-loads nothing for an owner session, and what --only names', async () => {
  // given an owner session and a secret in the default tier
  succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  succeeds(await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  const length = [process.execPath, '-e', 'console.log((process.env.OPENAI ?? "").length)']

  // then an owner holds no tier directly, as in direct mode: only --only loads it
  expect(succeeds(await cli(['run', '--', ...length], owner)).stdout).toBe('0\n')
  expect(succeeds(await cli(['run', '--only', 'typevault://openai', '--', ...length], owner)).stdout).toBe('9\n')
})

it('accumulates repeated --only flags and warns for unmatched patterns', async () => {
  succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  succeeds(await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  succeeds(await cli(['set', 'typevault://stripe', '--preset', 'api_key', '--stdin'], owner, 'sk-test-2'))
  const command = [
    process.execPath,
    '-e',
    'console.log([process.env.OPENAI, process.env.STRIPE].filter(Boolean).length)',
  ]

  const result = succeeds(
    await cli(
      [
        'run',
        '--only',
        'typevault://openai',
        '--only',
        'typevault://stripe',
        '--only',
        'typevault://missing',
        '--',
        ...command,
      ],
      owner,
    ),
  )
  expect(result.stdout).toBe('2\n')
  expect(result.stderr).toContain('typevault://missing')
})

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

it('replaces a daemon that holds no session when its owner unlocks', async () => {
  // given a daemon for this checkout that holds no session: here a machine member's, started without a password
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
  const { key } = JSON.parse(readFileSync(join(base, 'ci', 'typevault', 'identity.json'), 'utf8'))
  succeeds(await cli(['daemon', 'start'], { ...owner, TYPEVAULT_KEY: key }))
  expect((await cli(['ls'], owner)).stderr).toContain('the vault is locked')

  // when the owner unlocks
  const unlocked = succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))

  // then the session replaced that daemon, and the owner's commands go through it
  expect(unlocked.stdout).toContain('unlocked vault')
  succeeds(await cli(['set', 'typevault://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  expect(JSON.parse(succeeds(await cli(['ls', '--json'], owner)).stdout)).toMatchObject([{ name: 'openai' }])
}, 30_000)
