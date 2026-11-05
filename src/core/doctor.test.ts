import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from './admin'
import type { SecretKey } from './crypto'
import { doctor } from './doctor'
import { sealEntry, signerOf } from './entries'
import { createIdentity } from './identity'
import { type Founder, founderOf, initGlobalVault } from './init'
import { globalLayout } from './layout'
import { parseEntryName } from './naming'
import { Vault } from './vault'

const envIn = (dir: string) => ({ TYPEVAULT_DIR: join(dir, 'vault'), XDG_CONFIG_HOME: dir })

const machineFounder = async (): Promise<Founder> => founderOf((await createIdentity('owner', 'machine')).identity)

let root: string
let owner: SecretKey
let vault: Vault
const name = parseEntryName('openai')

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'typevault-doctor-'))
  owner = (await initGlobalVault(await machineFounder(), envIn(root))).owner
  vault = await Vault.open(globalLayout(envIn(root)), [owner], {})
  await new Admin(vault).addTier('team')
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

it('resolves a git merge conflict by keeping the highest valid revision', async () => {
  const first = await vault.put(
    { name, fields: { key: { type: 'secret' as const, value: 'one' } }, tier: 'team' },
    signerOf(owner),
  )
  const second = await vault.put(
    { name, fields: { key: { type: 'secret' as const, value: 'two' } }, tier: 'team' },
    signerOf(owner),
  )
  const file = join(root, 'vault', 'entries', `${second.envelope.id}.json`)
  const ours = JSON.stringify(first.envelope, null, 2)
  const theirs = JSON.stringify(second.envelope, null, 2)
  writeFileSync(file, `<<<<<<< HEAD\n${ours}\n=======\n${theirs}\n>>>>>>> branch\n`)

  const report = await doctor(vault, true)

  expect(report.mergesResolved).toEqual([`${second.envelope.id}.json`])
  expect(JSON.parse(readFileSync(file, 'utf8')).rev).toBe(2)
  expect((await vault.find(name))?.payload.fields).toEqual({ key: { type: 'secret' as const, value: 'two' } })
})

it.each(['main', 'incoming'])('resolves every hunk from a real git merge on %s', async (branch) => {
  const git = async (...args: string[]): Promise<number> => {
    const proc = Bun.spawn(
      ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', ...args],
      {
        cwd: vault.layout.entries,
        env: {
          PATH: process.env['PATH'],
          HOME: root,
          GIT_MASTER: '1',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: join(root, 'gitconfig'),
        },
        stdin: 'ignore',
        stdout: 'ignore',
        stderr: 'ignore',
        timeout: 10_000,
      },
    )
    return proc.exited
  }
  const tier = await vault.keyring.unlock('team')
  if (tier === undefined) throw new Error('team key is unavailable')
  const signer = signerOf(tier)
  const base = await vault.put(
    { name, fields: { key: { type: 'secret' as const, value: 'base' } }, tier: 'team' },
    signer,
  )
  const file = join(vault.layout.entries, `${base.envelope.id}.json`)
  const side = (rev: number, value: string) =>
    sealEntry(
      {
        ...base.envelope,
        rev,
        at: new Date(Date.parse(base.envelope.at) + rev).toISOString(),
        payload: { ...base.payload, fields: { key: { type: 'secret' as const, value } } },
      },
      vault.state,
      signer,
    )
  const newest = await side(3, 'newest')
  const older = await side(2, 'older')
  expect(await git('init', '-q', '-b', 'main')).toBe(0)
  expect(await git('add', '.')).toBe(0)
  expect(await git('commit', '-qm', 'base')).toBe(0)
  expect(await git('checkout', '-qb', 'incoming')).toBe(0)
  writeFileSync(file, `${JSON.stringify(newest, null, 2)}\n`)
  expect(await git('commit', '-qam', 'incoming')).toBe(0)
  expect(await git('checkout', '-q', 'main')).toBe(0)
  writeFileSync(file, `${JSON.stringify(older, null, 2)}\n`)
  expect(await git('commit', '-qam', 'main')).toBe(0)
  expect(await git('checkout', '-q', branch)).toBe(0)
  expect(await git('merge', branch === 'main' ? 'incoming' : 'main')).toBe(1)
  expect(readFileSync(file, 'utf8').match(/^<<<<<<< /gm)).toHaveLength(2)

  const report = await doctor(vault, true)

  expect(report.problems).toEqual([])
  expect(report.mergesResolved).toEqual([`${newest.id}.json`])
  expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual(newest)
  expect((await vault.find(name))?.payload.fields).toEqual({ key: { type: 'secret' as const, value: 'newest' } })
})

it('removes the older copy when two files hold the same name', async () => {
  await vault.put({ name, fields: { key: { type: 'secret' as const, value: 'zero' } }, tier: 'team' }, signerOf(owner))
  const kept = await vault.put(
    { name, fields: { key: { type: 'secret' as const, value: 'one' } }, tier: 'team' },
    signerOf(owner),
  )
  const payload = { ...kept.payload, fields: { key: { type: 'secret' as const, value: 'stale' } } }
  const stale = await sealEntry(
    { id: `team.${'f'.repeat(32)}`, tier: 'team', rev: 1, at: '2020-01-01T00:00:00.000Z', payload },
    vault.state,
    signerOf(owner),
  )
  writeFileSync(join(root, 'vault', 'entries', `${stale.id}.json`), JSON.stringify(stale))

  const report = await doctor(vault, true)

  expect(report.duplicatesRemoved).toEqual([`openai (team, ${stale.id})`])
  expect((await vault.scan()).entries).toHaveLength(1)
})

it('never deletes a copy that lives in another tier', async () => {
  await new Admin(vault).addTier('other')
  const kept = await vault.put(
    { name, fields: { key: { type: 'secret' as const, value: 'one' } }, tier: 'team' },
    signerOf(owner),
  )
  const payload = { ...kept.payload, fields: { key: { type: 'secret' as const, value: 'planted' } } }
  const planted = await sealEntry(
    { id: `other.${'e'.repeat(32)}`, tier: 'other', rev: 99, at: kept.envelope.at, payload },
    vault.state,
    signerOf(owner),
  )
  writeFileSync(join(root, 'vault', 'entries', `${planted.id}.json`), JSON.stringify(planted))

  const report = await doctor(vault, true)

  expect(report.duplicatesRemoved).toEqual([])
  expect(report.duplicatesKept).toEqual(['openai (in other, team)'])
  expect((await vault.scan()).entries).toHaveLength(2)
})
