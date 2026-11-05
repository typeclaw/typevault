import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { GrantStore } from '../daemon/grants'
import type { SecretKey } from './crypto'
import { TypeVaultError } from './errors'
import { refuseForeignDaemon } from './holder'
import { createIdentity } from './identity'
import { founderOf, initGlobalVault } from './init'
import { globalLayout, type Layout } from './layout'
import { loadState, signedDoc } from './state'

let root: string
let layout: Layout
let owner: SecretKey

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'tv-state-'))
  const env = { TYPEVAULT_DIR: join(root, 'vault'), XDG_CONFIG_HOME: root }
  const { identity } = await createIdentity('owner', 'machine')
  owner = (await initGlobalVault(founderOf(identity), env)).owner
  layout = globalLayout(env)
  mkdirSync(layout.run, { recursive: true })
})

afterEach(() => rmSync(root, { recursive: true, force: true }))

for (const text of ['', '{"host":"x","pid":12', '{}']) {
  it(`identifies a corrupt holder file for ${JSON.stringify(text)}`, () => {
    writeFileSync(layout.daemonHolder, text)

    expect(() => refuseForeignDaemon(layout, {})).toThrow(TypeVaultError)
    expect(() => refuseForeignDaemon(layout, {})).toThrow(
      expect.objectContaining({ code: 'tampered', message: expect.stringContaining(layout.daemonHolder) }),
    )
  })
}

for (const text of ['', '[', '{}']) {
  it(`identifies corrupt persisted grants for ${JSON.stringify(text)}`, () => {
    writeFileSync(layout.grantsFile, text)

    expect(() => new GrantStore(layout.grantsFile)).toThrow(
      expect.objectContaining({ code: 'tampered', message: expect.stringContaining(layout.grantsFile) }),
    )
  })
}

for (const file of [
  'ownerFile',
  'tiersFile',
  'membersFile',
  'signersFile',
  'ceilingsFile',
  'trustFile',
  'revisionsFile',
] as const) {
  it(`identifies malformed ${file} without accepting it`, () => {
    loadState(layout, {})
    const path = layout[file]
    writeFileSync(path, '<<<<<<< HEAD\n{}\n=======\n{}\n>>>>>>> branch\n')

    expect(() => loadState(layout, {})).toThrow(
      expect.objectContaining({ code: 'tampered', message: expect.stringContaining(path) }),
    )
  })
}

it('identifies a manifest whose signature is missing', () => {
  const doc = JSON.parse(readFileSync(layout.tiersFile, 'utf8'))
  // An invalid document envelope is still corruption, before any signature can be checked.
  writeFileSync(layout.tiersFile, JSON.stringify({ body: doc.body }))

  expect(() => loadState(layout, {})).toThrow(
    expect.objectContaining({ code: 'tampered', message: expect.stringContaining(layout.tiersFile) }),
  )
})

it('identifies an owner-signed manifest with an invalid body', () => {
  writeFileSync(layout.tiersFile, signedDoc({ v: 1, seq: 1, tiers: [] }, owner))

  expect(() => loadState(layout, {})).toThrow(
    expect.objectContaining({ code: 'tampered', message: expect.stringContaining(layout.tiersFile) }),
  )
})
