import { afterEach, beforeEach, expect, it } from 'bun:test'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { initLocalVault, initVault } from './init'
import { layoutOf } from './layout'

function plantOldVault(vaultDir: string): void {
  mkdirSync(vaultDir, { recursive: true })
  writeFileSync(join(vaultDir, 'operator.json'), '{}')
}

let base: string

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'typevault-init-'))
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

it('keeps a project vault committable and its keys under the typevault root', async () => {
  const layout = await initLocalVault(join(base, 'project', '.typevault'), { XDG_CONFIG_HOME: join(base, 'config') })

  expect(layout.vault).toBe(join(base, 'project', '.typevault'))
  expect(layout.keys.startsWith(join(base, 'config', 'typevault', 'vaults'))).toBe(true)
  expect(layout.root.startsWith(join(base, 'config', 'typevault', 'checkouts'))).toBe(true)
  expect(readdirSync(layout.vault).sort()).toEqual([
    'ceilings.json',
    'entries',
    'groups.json',
    'owner.json',
    'signers.json',
  ])
  expect(readdirSync(layout.keys)).toContain('owner.key')
})

it('refuses to init over an old-format project vault without writing anything', async () => {
  // given
  const dir = join(base, 'project', '.typevault')
  plantOldVault(dir)

  // when
  const init = initLocalVault(dir, { XDG_CONFIG_HOME: join(base, 'config') })

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
  const init = initVault(root)

  // then
  await expect(init).rejects.toThrow('old-format vault')
  expect(existsSync(ownerFile)).toBe(false)
})
