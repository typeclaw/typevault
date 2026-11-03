import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from './admin'
import type { SecretKey } from './crypto'
import { doctor } from './doctor'
import { sealEntry, signerOf } from './entries'
import { initVault } from './init'
import { layoutOf } from './layout'
import { parseEntryName } from './naming'
import { Vault } from './vault'

let root: string
let owner: SecretKey
let vault: Vault
const name = parseEntryName('openai')

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'typevault-doctor-'))
  owner = await initVault(root)
  vault = await Vault.open(layoutOf(root), [owner], {})
  await new Admin(vault).addTier('team')
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

it('resolves a git merge conflict by keeping the highest valid revision', async () => {
  const first = await vault.put({ name, type: 'api_key', fields: { key: 'one' }, tier: 'team' }, signerOf(owner))
  const second = await vault.put({ name, type: 'api_key', fields: { key: 'two' }, tier: 'team' }, signerOf(owner))
  const file = join(root, 'vault', 'entries', `${second.envelope.id}.json`)
  const ours = JSON.stringify(first.envelope, null, 2)
  const theirs = JSON.stringify(second.envelope, null, 2)
  writeFileSync(file, `<<<<<<< HEAD\n${ours}\n=======\n${theirs}\n>>>>>>> branch\n`)

  const report = await doctor(vault, true)

  expect(report.mergesResolved).toEqual([`${second.envelope.id}.json`])
  expect(JSON.parse(readFileSync(file, 'utf8')).rev).toBe(2)
  expect((await vault.find(name))?.payload.fields).toEqual({ key: 'two' })
})

it('removes the older copy when two files hold the same name', async () => {
  await vault.put({ name, type: 'api_key', fields: { key: 'zero' }, tier: 'team' }, signerOf(owner))
  const kept = await vault.put({ name, type: 'api_key', fields: { key: 'one' }, tier: 'team' }, signerOf(owner))
  const payload = { ...kept.payload, fields: { key: 'stale' } }
  const stale = await sealEntry(
    { id: 'f'.repeat(32), tier: 'team', rev: 1, at: '2020-01-01T00:00:00.000Z', payload },
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
  const kept = await vault.put({ name, type: 'api_key', fields: { key: 'one' }, tier: 'team' }, signerOf(owner))
  const payload = { ...kept.payload, fields: { key: 'planted' } }
  const planted = await sealEntry(
    { id: 'e'.repeat(32), tier: 'other', rev: 99, at: kept.envelope.at, payload },
    vault.state,
    signerOf(owner),
  )
  writeFileSync(join(root, 'vault', 'entries', `${planted.id}.json`), JSON.stringify(planted))

  const report = await doctor(vault, true)

  expect(report.duplicatesRemoved).toEqual([])
  expect(report.duplicatesKept).toEqual(['openai (in other, team)'])
  expect((await vault.scan()).entries).toHaveLength(2)
})
