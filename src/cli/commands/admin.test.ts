import { afterEach, beforeEach, expect, it, setSystemTime } from 'bun:test'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { issueSealedGrant, readSealedGrant, sealedSigningSecret } from '../../access/sealed'
import { Admin } from '../../core/admin'
import { createIdentity, writeIdentity } from '../../core/identity'
import { founderOf, initVault } from '../../core/init'
import { layoutOf } from '../../core/layout'
import { parseEntryName } from '../../core/naming'
import { Vault } from '../../core/vault'

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
  // Short root: the daemon's unix socket path is limited to ~104 bytes.
  base = realpathSync(mkdtempSync('/tmp/tvc-'))
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
  const locked = await cli(['set', 'tv://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1')
  expect({ code: locked.code, stderr: locked.stderr }).toEqual({
    code: 1,
    stderr: 'typevault: the vault is locked: ask a human to run `typevault unlock`\n',
  })

  // when the owner unlocks it
  succeeds(await cli(['unlock', '--for', '10m', '--vault-password-stdin'], owner, `${PASSWORD}\n`))

  // then commands go through the session until it is locked again
  succeeds(await cli(['set', 'tv://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  expect(JSON.parse(succeeds(await cli(['ls', '--json'], owner)).stdout)).toMatchObject([{ name: 'openai' }])
  succeeds(await cli(['lock'], owner))
  expect((await cli(['ls'], owner)).stderr).toContain('the vault is locked')
})

it.each(['github/late', 'TV://GitHub/Late', 'typevault://github/late'])(
  'keeps an expired sealed write only when doctor --adopt-expired names it (as %p)',
  async (named) => {
    // given a machine-owned vault holding a write from a sealed grant that expired an hour ago
    const root = join(base, 'm')
    const { identity } = await createIdentity('owner', 'machine')
    writeIdentity({ TYPEVAULT_DIR: root }, identity)
    const vault = await Vault.open(layoutOf(root), [(await initVault(root, founderOf(identity))).owner], {})
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
    const env = { PATH: owner['PATH'] ?? '', TYPEVAULT_DIR: root }

    // when the owner runs doctor --fix without naming it, then naming it
    const skipped = await cli(['doctor', '--fix'], env)
    const adopted = succeeds(await cli(['doctor', '--fix', '--adopt-expired', named], env))

    // then it is listed and left alone, then adopted
    expect(skipped.stdout).toContain('expired sealed write: github/late')
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
  succeeds(await cli(['set', 'tv://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))

  // when a machine joins and the owner adds it with the line join printed
  const machine = { PATH: owner['PATH'] ?? '', XDG_CONFIG_HOME: join(base, 'ci') }
  const joined = succeeds(await cli(['join', '--machine', '--name', 'ci'], machine))
  const publicKey = joined.stdout.split(' ').find((word) => word.startsWith('tvp1:')) ?? ''
  const added = ['member', 'add', 'ci', publicKey, '--tier', 'default', '--vault-password-stdin']
  succeeds(await cli(added, owner, `${PASSWORD}\n`))

  // then the machine reads the secret directly
  const read = succeeds(await cli(['get', 'tv://openai', '--reveal'], machine))
  expect(read.stdout).toBe('sk-test-1\n')
})

it('bulk-loads nothing for an owner session, and what --only names', async () => {
  // given an owner session and a secret in the default tier
  succeeds(await cli(['unlock', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  succeeds(await cli(['set', 'tv://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  const length = ['sh', '-c', 'echo ${#OPENAI}']

  // then an owner holds no tier directly, as in direct mode: only --only loads it
  expect(succeeds(await cli(['run', '--', ...length], owner)).stdout).toBe('0\n')
  expect(succeeds(await cli(['run', '--only', 'tv://openai', '--', ...length], owner)).stdout).toBe('9\n')
})

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
  succeeds(await cli(['set', 'tv://openai', '--preset', 'api_key', '--stdin'], owner, 'sk-test-1'))
  expect(JSON.parse(succeeds(await cli(['ls', '--json'], owner)).stdout)).toMatchObject([{ name: 'openai' }])
}, 30_000)
