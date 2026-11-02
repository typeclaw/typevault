import { existsSync, readFileSync } from 'node:fs'

import { z } from 'zod'

import { atomicWrite } from './fsx'

const MarksSchema = z.record(z.string(), z.number().int())

/**
 * The highest revision this machine has seen per entry id. Every old revision is still validly signed in git
 * history, so swapping a file back to one is caught here, locally, rather than trusted.
 */
export class RevisionMarks {
  readonly #path: string
  readonly #marks: Record<string, number>
  #dirty = false

  constructor(path: string) {
    this.#path = path
    this.#marks = existsSync(path) ? MarksSchema.parse(JSON.parse(readFileSync(path, 'utf8'))) : {}
  }

  /** False when `rev` is older than a revision already seen for `id`; otherwise records it. */
  accept(id: string, rev: number): boolean {
    const seen = this.#marks[id] ?? 0
    if (rev < seen) return false
    if (rev > seen) {
      this.#marks[id] = rev
      this.#dirty = true
    }
    return true
  }

  save(): void {
    if (this.#dirty) atomicWrite(this.#path, JSON.stringify(this.#marks), 0o600)
    this.#dirty = false
  }
}
