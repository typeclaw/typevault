import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { type Layout, layoutOf } from '../core/layout'
import { anchorAudit, appendAudit, readAudit, verifyAudit } from './log'

let layout: Layout
beforeEach(() => {
  layout = layoutOf(mkdtempSync(join(tmpdir(), 'typevault-audit-')))
})
afterEach(() => rmSync(layout.root, { recursive: true, force: true }))

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

it('detects a rewritten log that no longer matches its anchor', async () => {
  await read(['github/bot'])
  await anchorAudit(layout)
  rmSync(layout.auditLog)
  await appendAudit(layout, { action: 'read', mode: 'live', entries: ['other'] })
  expect(verifyAudit(layout)).toEqual({ ok: false, reason: 'local log no longer matches the anchor at record 1' })
})
