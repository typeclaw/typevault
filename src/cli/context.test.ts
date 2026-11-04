import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from '../core/admin'
import { signerOf } from '../core/entries'
import { createIdentity } from '../core/identity'
import { type Founder, founderOf, initGlobalVault, initLocalVault } from '../core/init'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { findLayout, layoutFrom } from './context'

const machineFounder = async (): Promise<Founder> => founderOf((await createIdentity('owner', 'machine')).identity)

let base: string
let project: string
let env: Record<string, string>

beforeEach(() => {
  base = realpathSync(mkdtempSync(join(tmpdir(), 'typevault-context-')))
  project = join(base, 'project')
  mkdirSync(join(project, 'src', 'deep'), { recursive: true })
  env = { HOME: base, XDG_CONFIG_HOME: join(base, 'config') }
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

it('finds the project vault from a nested directory and reads it with the keys kept outside', async () => {
  // given a project vault holding one entry
  const { layout: created, owner } = await initLocalVault(join(project, '.typevault'), await machineFounder(), env)
  const writer = await Vault.open(created, [owner], env)
  await new Admin(writer).addTier('member')
  const input = {
    name: parseEntryName('openai'),
    fields: { key: { type: 'secret' as const, value: 'sk-x' } },
    tier: 'member',
  } as const
  await writer.put(input, signerOf(owner))

  // when it is looked up from a nested directory
  const layout = layoutFrom(env, join(project, 'src', 'deep'))
  const found = await (await Vault.open(layout, [owner], env)).find(parseEntryName('openai'))

  // then it is the same vault and the entry reads back
  expect(layout).toMatchObject({ scope: 'local', vault: created.vault, root: created.root })
  expect(found?.payload.fields).toEqual({ key: { type: 'secret' as const, value: 'sk-x' } })
})

it('never takes the global vault in the home directory for a project vault above the project', async () => {
  // given a global vault in the home directory the project sits in
  const { layout: global } = await initGlobalVault(await machineFounder(), env)

  // then it is found only with -g
  expect(findLayout(env, project)).toBeUndefined()
  expect(() => layoutFrom(env, project)).toThrow(expect.objectContaining({ code: 'not_found' }))
  expect(layoutFrom({ ...env, TYPEVAULT_GLOBAL: '1' }, project)).toMatchObject({
    scope: 'global',
    vault: join(base, '.typevault'),
    root: global.root,
  })
})

it('selects the global vault with -g even inside a project', async () => {
  await initLocalVault(join(project, '.typevault'), await machineFounder(), env)

  expect(layoutFrom({ ...env, TYPEVAULT_GLOBAL: '1' }, project).scope).toBe('global')
  expect(layoutFrom({ TYPEVAULT_DIR: join(base, 'elsewhere') }, project).vault).toBe(join(base, 'elsewhere'))
})
