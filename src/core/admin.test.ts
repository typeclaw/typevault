import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { runAdminOp, UncertainChange } from './admin'
import { Admin } from './admin'
import type { SecretKey } from './crypto'
import { signerOf } from './entries'
import { createIdentity, memberPublicOfIdentity } from './identity'
import { founderOf, initGlobalVault } from './init'
import { globalLayout, type Layout } from './layout'
import { parseEntryName } from './naming'
import { recoverTxns } from './txn'
import { Vault } from './vault'

let base: string
let layout: Layout
let owner: SecretKey

beforeEach(async () => {
  base = mkdtempSync(join(tmpdir(), 'tva-'))
  const env = { TYPEVAULT_DIR: join(base, 'vault'), XDG_CONFIG_HOME: base }
  layout = globalLayout(env)
  owner = (await initGlobalVault(founderOf((await createIdentity('owner', 'machine')).identity), env)).owner
  const vault = await Vault.open(layout, [owner], {})
  await new Admin(vault).addTier('member')
  await vault.put(
    { name: parseEntryName('openai'), fields: { key: { type: 'secret', value: 'sk-test' } }, tier: 'member' },
    signerOf(owner),
  )
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

it('keeps the result of a committed rotation when the vault cannot be reloaded after it', async () => {
  // given a vault whose reload fails once it would see the rotated tier: the reload right after the commit
  const vault = await Vault.open(layout, [owner], {})
  const gen = vault.state.tiers['member']?.gen
  const reload = vault.reload.bind(vault)
  vault.reload = () => {
    reload()
    if (vault.state.tiers['member']?.gen !== gen) throw new Error('cannot save revision marks')
  }

  // when the tier is rotated
  const result = await runAdminOp(vault, { op: 'key.rotate', name: 'member' })

  // then the result still names what to rotate at the source, the rotation landed, and the reload failure is reported
  expect(result).toEqual({ affected: ['openai'], removed: [], ownerRotated: false, reloaded: false })
  expect((await Vault.open(layout, [], {})).state.tiers['member']?.gen).toBe((gen ?? 0) + 1)
})

it('reports the owner rotation of a removal its vault handle had not seen coming', async () => {
  // given a vault handle opened before another writer adds Bob as an owner
  const vault = await Vault.open(layout, [owner], {})
  const { identity } = await createIdentity('bob', 'machine')
  await new Admin(await Vault.open(layout, [owner], {})).addMember('bob', {
    ...memberPublicOfIdentity(identity),
    owner: true,
    tiers: [],
  })

  // when that handle removes Bob
  const result = await runAdminOp(vault, { op: 'member.rm', name: 'bob' })

  // then its result names Bob and the owner rotation the removal made, as found under its own lock
  expect(result).toMatchObject({ removed: ['bob'], ownerRotated: true, reloaded: true })
})

it('reports a change committed by its marker but not yet written as uncertain, never as failed', async () => {
  // given a file where the new tier's directory must go, so writing it fails after the commit marker
  const vault = await Vault.open(layout, [owner], {})
  mkdirSync(join(layout.vault, 'tiers'), { recursive: true })
  writeFileSync(join(layout.vault, 'tiers', 'ops'), 'in the way')

  // when the tier is added, the outcome is uncertain
  const adding = runAdminOp(vault, { op: 'tier.add', name: 'ops' })
  await expect(adding).rejects.toBeInstanceOf(UncertainChange)
  await expect(adding).rejects.toMatchObject({ code: 'unavailable' })

  // then once the way is clear, recovery finishes the committed change
  rmSync(join(layout.vault, 'tiers', 'ops'))
  recoverTxns(layout)
  expect((await Vault.open(layout, [], {})).state.tiers['ops']).toBeDefined()
})
