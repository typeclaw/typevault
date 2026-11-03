import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from '../../core/admin'
import { decodeSecretKey } from '../../core/crypto'
import { initVault } from '../../core/init'
import { layoutOf } from '../../core/layout'
import { Vault } from '../../core/vault'
import { findLayout } from '../context'

const CLI = join(import.meta.dir, '..', 'index.ts')

let base: string

beforeEach(() => {
  base = realpathSync(mkdtempSync(join(tmpdir(), 'typevault-cli-init-')))
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

it('creates the starter tier with the new vault owner key, even with an inherited TYPEVAULT_KEY', async () => {
  // given a tier key for some other vault in the environment
  const otherRoot = join(base, 'other')
  const otherOwner = await initVault(otherRoot)
  const other = new Admin(await Vault.open(layoutOf(otherRoot), [otherOwner], {}))
  await other.addTier('member')
  const env = { PATH: process.env['PATH'] ?? '', XDG_CONFIG_HOME: join(base, 'config') }
  const project = join(base, 'project')
  mkdirSync(project)

  // when a project vault is initialized
  const proc = Bun.spawn([process.execPath, CLI, 'init'], {
    cwd: project,
    env: { ...env, TYPEVAULT_KEY: await other.exportKey('member') },
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const [code, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()])

  // then it succeeds and the new vault holds the default tier
  expect({ code, stderr: code === 0 ? '' : stderr }).toEqual({ code: 0, stderr: '' })
  const layout = findLayout(env, project)
  if (layout === undefined) throw new Error('no vault was created')
  const owner = decodeSecretKey(readFileSync(layout.ownerKey, 'utf8'))
  expect(Object.keys((await Vault.open(layout, [owner], env)).state.tiers)).toEqual(['default'])
})
