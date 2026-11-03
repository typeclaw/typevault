import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { dirname, isAbsolute, join, normalize, sep } from 'node:path'

import { z } from 'zod'

import { randomHex } from './crypto'
import { fromUtf8, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { assertNoSymlinks, atomicWrite, fsyncDir } from './fsx'
import type { Layout } from './layout'

const COMMITTED = 'COMMITTED'
const ManifestSchema = z.object({ puts: z.array(z.string()), removes: z.array(z.string()) })

/**
 * A batch of vault file changes that lands all-or-nothing. Puts apply in insertion order and
 * removes after them, so a caller flips a pointer file (tiers.json) by putting it last.
 * Mutable on purpose: it accumulates changes until `commitTxn`.
 */
export class Txn {
  readonly puts = new Map<string, Uint8Array>()
  readonly removes = new Set<string>()

  put(rel: string, data: Uint8Array | string): this {
    const path = checkRel(rel)
    this.puts.delete(path)
    this.puts.set(path, typeof data === 'string' ? utf8(data) : data)
    this.removes.delete(path)
    return this
  }

  remove(rel: string): this {
    const path = checkRel(rel)
    this.puts.delete(path)
    this.removes.add(path)
    return this
  }

  get isEmpty(): boolean {
    return this.puts.size === 0 && this.removes.size === 0
  }
}

function checkRel(rel: string): string {
  const path = normalize(rel)
  if (isAbsolute(path) || path === '..' || path.startsWith(`..${sep}`) || path.startsWith('.txn')) {
    throw new TypeVaultError('invalid', `refusing vault path outside the vault: ${rel}`)
  }
  return path
}

/** Stages every file, writes the commit marker, then applies. Caller must hold the exclusive vault lock. */
export function commitTxn(layout: Layout, txn: Txn): void {
  if (txn.isEmpty) return
  const dir = join(layout.txnDir, randomHex(8))
  mkdirSync(join(dir, 'files'), { recursive: true })
  const puts = [...txn.puts.keys()]
  puts.forEach((rel, index) => atomicWrite(join(dir, 'files', String(index)), txn.puts.get(rel) ?? new Uint8Array()))
  atomicWrite(join(dir, 'manifest.json'), JSON.stringify({ puts, removes: [...txn.removes] }))
  atomicWrite(join(dir, COMMITTED), '')
  applyTxn(layout, dir)
}

/** Idempotent: a crash halfway through is finished by running it again. */
function applyTxn(layout: Layout, dir: string): void {
  const manifest = ManifestSchema.parse(JSON.parse(fromUtf8(readFileSync(join(dir, 'manifest.json')))))
  const touched = new Set<string>()
  manifest.puts.forEach((rel, index) => {
    const staged = join(dir, 'files', String(index))
    if (!existsSync(staged)) return
    assertNoSymlinks(layout.vault, checkRel(rel))
    const target = join(layout.vault, checkRel(rel))
    // Staging (run/) and the vault may sit on different filesystems, where rename fails: write the bytes in place.
    atomicWrite(target, readFileSync(staged))
    rmSync(staged)
    touched.add(dirname(target))
  })
  for (const rel of manifest.removes) {
    assertNoSymlinks(layout.vault, checkRel(rel))
    const target = join(layout.vault, checkRel(rel))
    rmSync(target, { force: true, recursive: true })
    touched.add(dirname(target))
  }
  for (const path of touched) if (existsSync(path)) fsyncDir(path)
  rmSync(dir, { recursive: true, force: true })
}

/** Rolls forward transactions that reached their commit marker and discards the rest. Needs the exclusive lock. */
export function recoverTxns(layout: Layout): void {
  if (!existsSync(layout.txnDir)) return
  if (!lstatSync(layout.txnDir).isDirectory())
    throw new TypeVaultError('tampered', `${layout.txnDir} is not a directory`)
  for (const name of readdirSync(layout.txnDir)) {
    const dir = join(layout.txnDir, name)
    if (!lstatSync(dir).isDirectory()) throw new TypeVaultError('tampered', `${dir} is not a directory`)
    if (existsSync(join(dir, COMMITTED))) applyTxn(layout, dir)
    else rmSync(dir, { recursive: true, force: true })
  }
}
