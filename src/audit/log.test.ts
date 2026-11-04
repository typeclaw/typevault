import { afterEach, beforeEach, expect, it } from 'bun:test'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { globalLayout, type Layout } from '../core/layout'
import { anchorAudit, appendAudit, readAudit, verifyAudit } from './log'

let base: string
let layout: Layout
beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'typevault-audit-'))
  layout = globalLayout({ TYPEVAULT_DIR: join(base, 'vault'), XDG_CONFIG_HOME: base })
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

const read = (entries: readonly string[]) =>
  appendAudit(layout, { action: 'read', mode: 'live', label: 'session:a', entries })

it('chains records so the log verifies', async () => {
  await read(['github/bot'])
  await read(['openai'])
  expect(verifyAudit(layout)).toEqual({ ok: true, records: 2 })
  expect(readAudit(layout).map((record) => record.seq)).toEqual([1, 2])
})

it('detects an edited record', async () => {
  await read(['github/bot'])
  await read(['openai'])
  writeFileSync(layout.auditLog, readFileSync(layout.auditLog, 'utf8').replace('openai', 'stripe'))
  expect(verifyAudit(layout)).toEqual({ ok: false, reason: 'record 2 was modified' })
})

it('refuses to anchor through a symlinked anchors file', async () => {
  await read(['github/bot'])
  const outside = join(layout.root, 'outside.txt')
  writeFileSync(outside, 'mine\n')
  mkdirSync(dirname(layout.anchorsFile), { recursive: true })
  symlinkSync(outside, layout.anchorsFile)
  await expect(anchorAudit(layout)).rejects.toThrow('is a symlink')
  expect(readFileSync(outside, 'utf8')).toBe('mine\n')
})

it('refuses to anchor through a symlinked anchors directory', async () => {
  await read(['github/bot'])
  const outside = join(layout.root, 'outside')
  mkdirSync(outside)
  mkdirSync(layout.vault, { recursive: true })
  symlinkSync(outside, dirname(layout.anchorsFile))
  await expect(anchorAudit(layout)).rejects.toThrow('is a symlink')
  expect(readdirSync(outside)).toEqual([])
})

it('refuses to anchor through a dangling anchors-file symlink', async () => {
  await read(['github/bot'])
  const outside = join(layout.root, 'outside.txt')
  mkdirSync(dirname(layout.anchorsFile), { recursive: true })
  symlinkSync(outside, layout.anchorsFile)
  await expect(anchorAudit(layout)).rejects.toThrow('is a symlink')
  expect(existsSync(outside)).toBe(false)
})

it('refuses to anchor through a symlinked vault', async () => {
  await read(['github/bot'])
  const outside = join(layout.root, 'outside')
  mkdirSync(outside)
  rmSync(layout.vault, { recursive: true, force: true })
  symlinkSync(outside, layout.vault)
  await expect(anchorAudit(layout)).rejects.toThrow('is a symlink')
  expect(readdirSync(outside)).toEqual([])
})

it('detects a rewritten log that no longer matches its anchor', async () => {
  await read(['github/bot'])
  await anchorAudit(layout)
  rmSync(layout.auditLog)
  await appendAudit(layout, { action: 'read', mode: 'live', entries: ['other'] })
  expect(verifyAudit(layout)).toEqual({ ok: false, reason: 'local log no longer matches the anchor at record 1' })
})
