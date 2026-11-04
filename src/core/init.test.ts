import { afterEach, beforeEach, expect, it } from 'bun:test'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { createIdentity } from './identity'
import { type Founder, founderOf, initLocalVault, initVault } from './init'
import { layoutOf } from './layout'
import { Vault } from './vault'

function plantOldVault(vaultDir: string): void {
  mkdirSync(vaultDir, { recursive: true })
  writeFileSync(join(vaultDir, 'operator.json'), '{}')
}

const founder = async (kind: 'human' | 'machine'): Promise<Founder> =>
  founderOf((await createIdentity('alice', kind, kind === 'human' ? 'correct horse' : undefined)).identity)

let base: string

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'typevault-init-'))
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

it('keeps every key of a project vault inside it, sealed, with only checkout state outside', async () => {
  // when a human founds a project vault
  const env = { XDG_CONFIG_HOME: join(base, 'config') }
  const { layout } = await initLocalVault(join(base, 'project', '.typevault'), await founder('human'), env)

  // then the committable part holds the owner wrap and the founder's sealed key, and nothing else is shared
  expect(layout.vault).toBe(join(base, 'project', '.typevault'))
  expect(layout.root.startsWith(join(base, 'config', 'typevault', 'checkouts'))).toBe(true)
  expect(readdirSync(layout.vault).sort()).toEqual([
    'ceilings.json',
    'entries',
    'members',
    'members.json',
    'owner',
    'owner.json',
    'signers.json',
    'tiers.json',
  ])
  expect(readdirSync(join(layout.vault, 'owner'))).toEqual(['alice.age'])
  expect(readdirSync(layout.membersDir)).toEqual(['alice.key'])
  expect(existsSync(join(base, 'config', 'typevault', 'vaults'))).toBe(false)
})

it('lists the founder as the only member, an owner', async () => {
  const { layout } = await initVault(join(base, 'global'), await founder('machine'))

  const { members } = (await Vault.open(layout, [], {})).state

  expect(Object.keys(members)).toEqual(['alice'])
  expect(members['alice']).toMatchObject({ kind: 'machine', owner: true, tiers: [] })
})

it('refuses to init over an old-format project vault without writing anything', async () => {
  // given
  const dir = join(base, 'project', '.typevault')
  plantOldVault(dir)

  // when
  const init = initLocalVault(dir, await founder('machine'), { XDG_CONFIG_HOME: join(base, 'config') })

  // then
  await expect(init).rejects.toThrow('old-format vault')
  expect(readdirSync(dir)).toEqual(['operator.json'])
})

it('refuses to init over an old-format global vault without writing anything', async () => {
  // given
  const root = join(base, 'global')
  const { ownerFile } = layoutOf(root)
  plantOldVault(dirname(ownerFile))

  // when
  const init = initVault(root, await founder('machine'))

  // then
  await expect(init).rejects.toThrow('old-format vault')
  expect(existsSync(ownerFile)).toBe(false)
})
