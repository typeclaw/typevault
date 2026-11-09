import { expect, it, setSystemTime } from 'bun:test'
import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

import { issueSealedGrant, readSealedGrant, sealedSigningSecret } from '../../access/sealed'
import { Admin } from '../../core/admin'
import { createIdentity, writeIdentity } from '../../core/identity'
import { founderOf, initGlobalVault } from '../../core/init'
import { globalLayout } from '../../core/layout'
import { parseEntryName } from '../../core/naming'
import { Vault } from '../../core/vault'
import { base, cli, envIn, owner, PASSWORD, succeeds } from './admin.harness'

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
