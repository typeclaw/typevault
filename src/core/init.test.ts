import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { initLocalVault } from './init'

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
    'operator.json',
    'signers.json',
  ])
  expect(readdirSync(layout.keys)).toContain('operator.key')
})
