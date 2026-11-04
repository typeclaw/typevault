import { afterEach, beforeEach, expect, it } from 'bun:test'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { globalLayout, type Layout } from './layout'
import { commitTxn, recoverTxns, Txn } from './txn'

let base: string
let layout: Layout

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'typevault-txn-'))
  layout = globalLayout({ TYPEVAULT_DIR: join(base, 'vault'), XDG_CONFIG_HOME: base })
  mkdirSync(layout.vault, { recursive: true })
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

function stage(id: string, committed: boolean): void {
  const dir = join(layout.txnDir, id)
  mkdirSync(join(dir, 'files'), { recursive: true })
  writeFileSync(join(dir, 'files', '0'), 'new')
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ puts: ['a/b.txt'], removes: ['old.txt'] }))
  if (committed) writeFileSync(join(dir, 'COMMITTED'), '')
}

it('applies puts and removes together', () => {
  writeFileSync(join(layout.vault, 'old.txt'), 'old')
  commitTxn(layout, new Txn().put('a/b.txt', 'new').remove('old.txt'))
  expect(readFileSync(join(layout.vault, 'a/b.txt'), 'utf8')).toBe('new')
  expect(existsSync(join(layout.vault, 'old.txt'))).toBe(false)
})

it('rolls a committed transaction forward on recovery', () => {
  writeFileSync(join(layout.vault, 'old.txt'), 'old')
  stage('t1', true)
  recoverTxns(layout)
  expect(readFileSync(join(layout.vault, 'a/b.txt'), 'utf8')).toBe('new')
  expect(existsSync(join(layout.vault, 'old.txt'))).toBe(false)
})

it('discards an uncommitted transaction on recovery', () => {
  writeFileSync(join(layout.vault, 'old.txt'), 'old')
  stage('t2', false)
  recoverTxns(layout)
  expect(existsSync(join(layout.vault, 'a/b.txt'))).toBe(false)
  expect(existsSync(join(layout.txnDir, 't2'))).toBe(false)
  expect(readFileSync(join(layout.vault, 'old.txt'), 'utf8')).toBe('old')
})

it('refuses paths that escape the vault', () => {
  expect(() => new Txn().put('../escape', 'x')).toThrow('outside the vault')
})

it('refuses a symlinked staging directory instead of deleting through it', () => {
  const victim = join(layout.root, 'victim')
  mkdirSync(join(victim, 'precious'), { recursive: true })
  mkdirSync(layout.run, { recursive: true })
  symlinkSync(victim, layout.txnDir)
  expect(() => recoverTxns(layout)).toThrow('is not a directory')
  expect(existsSync(join(victim, 'precious'))).toBe(true)
})
