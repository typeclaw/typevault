import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from './admin'
import type { SecretKey } from './crypto'
import { doctor } from './doctor'
import { sealEntry, signerOf } from './entries'
import { initVault } from './init'
import { parseEntryName } from './naming'
import { Vault } from './vault'

let root: string
let operator: SecretKey
let vault: Vault
const name = parseEntryName('openai')

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'typevault-doctor-'))
  operator = await initVault(root)
  vault = await Vault.open(root, [operator], {})
  await new Admin(vault).addGroup('team')
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

it('resolves a git merge conflict by keeping the highest valid revision', async () => {
  const first = await vault.put({ name, type: 'api_key', fields: { key: 'one' }, group: 'team' }, signerOf(operator))
  const second = await vault.put({ name, type: 'api_key', fields: { key: 'two' }, group: 'team' }, signerOf(operator))
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
  const kept = await vault.put({ name, type: 'api_key', fields: { key: 'one' }, group: 'team' }, signerOf(operator))
  const payload = { ...kept.payload, fields: { key: 'stale' } }
  const stale = await sealEntry(
    { id: 'f'.repeat(32), group: 'team', rev: 1, at: '2020-01-01T00:00:00.000Z', payload },
    vault.state,
    signerOf(operator),
  )
  writeFileSync(join(root, 'vault', 'entries', `${stale.id}.json`), JSON.stringify(stale))

  const report = await doctor(vault, true)

  expect(report.duplicatesRemoved).toEqual([`openai (${stale.id})`])
  expect((await vault.scan()).entries).toHaveLength(1)
})
