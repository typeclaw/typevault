import { appendFileSync, closeSync, existsSync, fsyncSync, openSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { sha256Hex } from '../core/crypto'
import { canonicalJson, type Json, utf8 } from '../core/encoding'
import { atomicWrite, ensureDir } from '../core/fsx'
import type { Layout } from '../core/layout'
import { withLock } from '../core/lock'

export type AuditMode = 'live' | 'sealed' | 'direct'

/** What happened, by whom. Metadata only: never a secret value. */
export type AuditEvent = {
  readonly action: string
  readonly mode: AuditMode
  readonly grant?: string
  readonly label?: string
  readonly groups?: readonly string[]
  readonly entries?: readonly string[]
  readonly reason?: string
}

const RecordSchema = z.looseObject({ seq: z.number().int(), at: z.string(), prev: z.string(), hash: z.string() })
const AnchorSchema = z.object({ seq: z.number().int(), hash: z.string(), at: z.string() })
export type AuditRecord = z.infer<typeof RecordSchema>

const GENESIS = '0'.repeat(64)
const ANCHOR_EVERY = 100

const hashOf = (record: Readonly<Record<string, Json>>): string => sha256Hex(utf8(canonicalJson(record)))

function appendLine(path: string, line: string): void {
  const fd = openSync(path, 'a', 0o600)
  try {
    appendFileSync(fd, `${line}\n`)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

const HeadSchema = z.object({ seq: z.number().int(), hash: z.string() })

/** The chain head, kept beside the log so an append never re-reads the whole trail. */
function readHead(layout: Layout): { readonly seq: number; readonly hash: string } | undefined {
  const path = join(layout.audit, 'head.json')
  if (existsSync(path)) return HeadSchema.parse(JSON.parse(readFileSync(path, 'utf8')))
  const last = readAudit(layout).at(-1)
  return last === undefined ? undefined : { seq: last.seq, hash: last.hash }
}

export function readAudit(layout: Layout): readonly AuditRecord[] {
  if (!existsSync(layout.auditLog)) return []
  return readFileSync(layout.auditLog, 'utf8')
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => RecordSchema.parse(JSON.parse(line)))
}

function writeAnchor(layout: Layout, last: AuditRecord): void {
  ensureDir(layout.vault)
  appendLine(layout.anchorsFile, JSON.stringify({ seq: last.seq, hash: last.hash, at: last.at }))
}

/** Appends one hash-chained record; every 100th record's head is anchored in the (committable) vault. */
export function appendAudit(layout: Layout, event: AuditEvent): Promise<void> {
  return withLock(layout.auditLock, 'exclusive', async () => {
    ensureDir(layout.audit, 0o700)
    const last = readHead(layout)
    const fields = Object.fromEntries(Object.entries(event).filter(([, value]) => value !== undefined))
    const unhashed = { ...fields, seq: (last?.seq ?? 0) + 1, at: new Date().toISOString(), prev: last?.hash ?? GENESIS }
    const record = { ...unhashed, hash: hashOf(unhashed) }
    appendLine(layout.auditLog, JSON.stringify(record))
    atomicWrite(join(layout.audit, 'head.json'), JSON.stringify({ seq: record.seq, hash: record.hash }), 0o600)
    if (record.seq % ANCHOR_EVERY === 0) writeAnchor(layout, record)
  })
}

/** Anchors the current head now, e.g. when the daemon stops. */
export function anchorAudit(layout: Layout): Promise<void> {
  return withLock(layout.auditLock, 'exclusive', async () => {
    const last = readAudit(layout).at(-1)
    if (last !== undefined) writeAnchor(layout, last)
  })
}

export type AuditVerdict =
  | { readonly ok: true; readonly records: number }
  | { readonly ok: false; readonly reason: string }

/** Recomputes the chain and checks every anchor against it. */
export function verifyAudit(layout: Layout): AuditVerdict {
  const records = readAudit(layout)
  let prev = GENESIS
  const heads = new Map<number, string>()
  for (const record of records) {
    const { hash, ...unhashed } = record
    if (record.prev !== prev) return { ok: false, reason: `record ${record.seq} does not follow its predecessor` }
    if (hashOf(z.record(z.string(), z.json()).parse(unhashed)) !== hash) {
      return { ok: false, reason: `record ${record.seq} was modified` }
    }
    heads.set(record.seq, hash)
    prev = hash
  }
  const anchors = existsSync(layout.anchorsFile)
    ? readFileSync(layout.anchorsFile, 'utf8')
        .split('\n')
        .filter((line) => line !== '')
        .map((line) => AnchorSchema.parse(JSON.parse(line)))
    : []
  const broken = anchors.find((anchor) => heads.get(anchor.seq) !== anchor.hash)
  if (broken !== undefined)
    return { ok: false, reason: `local log no longer matches the anchor at record ${broken.seq}` }
  return { ok: true, records: records.length }
}
