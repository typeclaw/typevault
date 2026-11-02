import { afterEach, beforeEach, expect, it } from 'bun:test'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { type Layout, layoutOf } from './layout'
import { commitTxn, recoverTxns, Txn } from './txn'

let layout: Layout

beforeEach(() => {
  layout = layoutOf(mkdtempSync(join(tmpdir(), 'typevault-txn-')))
  mkdirSync(layout.vault, { recursive: true })
})
afterEach(() => rmSync(layout.root, { recursive: true, force: true }))

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
