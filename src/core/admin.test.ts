import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { runAdminOp } from './admin'
import { Admin } from './admin'
import type { SecretKey } from './crypto'
import { signerOf } from './entries'
import { createIdentity } from './identity'
import { founderOf, initGlobalVault } from './init'
import { globalLayout, type Layout } from './layout'
import { parseEntryName } from './naming'
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
