import { afterEach, beforeEach, expect, it, mock } from 'bun:test'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import * as fsx from './fsx'
import { globalLayout, type Layout } from './layout'

// The commit marker's directory sync fails after its rename, as a full or failing disk can make it.
const atomicWrite = fsx.atomicWrite
let failMarkerSync = false
mock.module('./fsx', () => ({
  ...fsx,
  atomicWrite: (path: string, data: Uint8Array | string, mode?: number) => {
    atomicWrite(path, data, mode)
    if (failMarkerSync && path.endsWith('COMMITTED')) throw new Error('fsync failed')
  },
}))
const { commitTxn, MarkedCommitted, recoverTxns, Txn } = await import('./txn')
const { runAdminOp } = await import('./admin')
const { createIdentity } = await import('./identity')
const { founderOf, initGlobalVault } = await import('./init')
const { Vault } = await import('./vault')

let root: string
let layout: Layout
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'tvm-'))
  layout = globalLayout({ TYPEVAULT_DIR: join(root, 'vault'), XDG_CONFIG_HOME: root })
})
afterEach(() => {
  failMarkerSync = false
  rmSync(root, { recursive: true, force: true })
})

it('treats a marker that failed to sync after its rename as committed, and recovery finishes it', () => {
  // given a transaction whose commit marker fails to sync once renamed into place
  failMarkerSync = true

  // when it commits, the failure says it is committed, not that it failed
  expect(() => commitTxn(layout, new Txn().put('a.txt', 'new'))).toThrow(MarkedCommitted)

  // then recovery writes the change
  failMarkerSync = false
  recoverTxns(layout)
  expect(readFileSync(join(layout.vault, 'a.txt'), 'utf8')).toBe('new')
  expect(existsSync(layout.txnDir) ? readdirSync(layout.txnDir) : []).toEqual([])
})

it('reports an owner change whose marker failed to sync as committed, never as failed', async () => {
  // given a vault, and a commit marker that will fail to sync once renamed into place
  const env = { TYPEVAULT_DIR: join(root, 'vault'), XDG_CONFIG_HOME: root }
  const { owner } = await initGlobalVault(founderOf((await createIdentity('owner', 'machine')).identity), env)
  const vault = await Vault.open(layout, [owner], {})
  failMarkerSync = true

  // when a tier is added, the change is rolled forward under its lock and reported done
  expect(await runAdminOp(vault, { op: 'tier.add', name: 'ops' })).toMatchObject({ reloaded: true })
  expect((await Vault.open(layout, [], {})).state.tiers['ops']).toBeDefined()
})
