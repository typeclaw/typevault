import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { type Envelope, EnvelopeSchema, verifyEnvelope } from './entries'
import { atomicWrite } from './fsx'
import { withLock } from './lock'
import { resolveName, type ScanProblem, type Vault } from './vault'

export type DoctorReport = {
  readonly problems: readonly ScanProblem[]
  readonly mergesResolved: readonly string[]
  readonly duplicatesRemoved: readonly string[]
  /** Same name in several tiers: reported for the owner, never deleted automatically. */
  readonly duplicatesKept: readonly string[]
  readonly needsRotation: readonly string[]
}

const CONFLICT = /^<<<<<<< [^\n]*\n([\s\S]*?)^=======\n([\s\S]*?)^>>>>>>> [^\n]*\n?/gm

function parseSide(text: string): Envelope | undefined {
  try {
    const parsed = EnvelopeSchema.safeParse(JSON.parse(text))
    return parsed.success ? parsed.data : undefined
  } catch (error) {
    if (error instanceof SyntaxError) return undefined
    throw error
  }
}

/** Splits a git conflict in an entry file into both sides and keeps the highest validly signed revision. */
function resolveMerge(vault: Vault, file: string): boolean {
  const path = join(vault.layout.entries, file)
  const text = readFileSync(path, 'utf8')
  const ours = text.replace(CONFLICT, '$1')
  if (ours === text) return false
  const theirs = text.replace(CONFLICT, '$2')
  const sides = [ours, theirs]
    .map(parseSide)
    .filter((side): side is Envelope => side !== undefined && verifyEnvelope(side, vault.state) === undefined)
  const winner = sides.reduce<Envelope | undefined>(
    (best, side) =>
      best === undefined || side.rev > best.rev || (side.rev === best.rev && side.at > best.at) ? side : best,
    undefined,
  )
  if (winner === undefined) return false
  atomicWrite(path, `${JSON.stringify(winner, null, 2)}\n`)
  return true
}

/** Verifies every entry, resolves git merge conflicts and duplicate names. `fix` applies the repairs. */
export function doctor(vault: Vault, fix: boolean): Promise<DoctorReport> {
  return withLock(vault.layout.lockFile, 'exclusive', async () => {
    vault.refresh()
    const files = existsSync(vault.layout.entries) ? readdirSync(vault.layout.entries) : []
    const mergesResolved = fix ? files.filter((file) => file.endsWith('.json') && resolveMerge(vault, file)) : []
    const { entries, problems } = await vault.scan()
    const byName = Map.groupBy(entries, (entry) => entry.payload.name)
    const duplicatesRemoved: string[] = []
    const duplicatesKept: string[] = []
    for (const [name, copies] of byName) {
      if (copies.length < 2) continue
      // Only same-tier copies are removed: across tiers the higher tier already wins reads, and
      // the owner decides what to delete.
      for (const [tier, inTier] of Map.groupBy(copies, (entry) => entry.envelope.tier)) {
        const keep = resolveName(vault.state.tiers, inTier)
        for (const copy of inTier) {
          if (copy === keep) continue
          if (fix) rmSync(join(vault.layout.entries, `${copy.envelope.id}.json`))
          duplicatesRemoved.push(`${name} (${tier}, ${copy.envelope.id})`)
        }
      }
      const tiers = new Set(copies.map((entry) => entry.envelope.tier))
      if (tiers.size > 1) duplicatesKept.push(`${name} (in ${[...tiers].sort().join(', ')})`)
    }
    const needsRotation = entries
      .filter((entry) => entry.payload.needsRotation === true)
      .map((entry) => entry.payload.name)
    return { problems, mergesResolved, duplicatesRemoved, duplicatesKept, needsRotation }
  })
}
