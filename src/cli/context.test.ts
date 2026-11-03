import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from '../core/admin'
import { decodeSecretKey } from '../core/crypto'
import { signerOf } from '../core/entries'
import { initLocalVault, initVault } from '../core/init'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { findLayout, layoutFrom } from './context'

let base: string
let project: string
let env: Record<string, string>

beforeEach(() => {
  base = realpathSync(mkdtempSync(join(tmpdir(), 'typevault-context-')))
  project = join(base, 'project')
  mkdirSync(join(project, 'src', 'deep'), { recursive: true })
  env = { XDG_CONFIG_HOME: join(base, 'config') }
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

it('finds the project vault from a nested directory and reads it with the keys kept outside', async () => {
  // given a project vault holding one entry
  const created = await initLocalVault(join(project, '.typevault'), env)
  const owner = decodeSecretKey(readFileSync(created.ownerKey, 'utf8'))
  const writer = await Vault.open(created, [owner], env)
  await new Admin(writer).addGroup('member')
  const input = { name: parseEntryName('openai'), type: 'api_key', fields: { key: 'sk-x' }, group: 'member' } as const
  await writer.put(input, signerOf(owner))

  // when it is looked up from a nested directory
  const layout = layoutFrom(env, join(project, 'src', 'deep'))
  const found = await (await Vault.open(layout, [owner], env)).find(parseEntryName('openai'))

  // then it is the same vault and the entry reads back
  expect(layout).toMatchObject({ scope: 'local', vault: created.vault, root: created.root })
  expect(found?.payload.fields).toEqual({ key: 'sk-x' })
})

it('never falls back to the global vault without -g', async () => {
  await initVault(join(base, 'config', 'typevault'))

  expect(findLayout(env, project)).toBeUndefined()
  expect(() => layoutFrom(env, project)).toThrow(expect.objectContaining({ code: 'not_found' }))
  expect(layoutFrom({ ...env, TYPEVAULT_GLOBAL: '1' }, project)).toMatchObject({
    scope: 'global',
    root: join(base, 'config', 'typevault'),
  })
})

it('selects the global vault with -g even inside a project', async () => {
  await initLocalVault(join(project, '.typevault'), env)

  expect(layoutFrom({ ...env, TYPEVAULT_GLOBAL: '1' }, project).scope).toBe('global')
  expect(layoutFrom({ TYPEVAULT_DIR: join(base, 'elsewhere') }, project).root).toBe(join(base, 'elsewhere'))
})
