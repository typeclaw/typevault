import { existsSync } from 'node:fs'

import { z } from 'zod'

import { atomicWrite } from './fsx'
import { readJsonFile } from './json-file'

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
    this.#marks = existsSync(path) ? readJsonFile(path, MarksSchema) : {}
  }

  /** False when `rev` is older than a revision already seen for `id`. */
  allows(id: string, rev: number): boolean {
    return rev >= (this.#marks[id] ?? 0)
  }

  /** Like `allows`, and records `rev` when it is. */
  accept(id: string, rev: number): boolean {
    if (!this.allows(id, rev)) return false
    if (rev > (this.#marks[id] ?? 0)) {
      this.#marks[id] = rev
      this.#dirty = true
    }
    return true
  }

  /** Marks `id` deleted: any file carrying it again (say, restored from git history) is refused here. */
  tombstone(id: string): void {
    this.#marks[id] = Number.MAX_SAFE_INTEGER
    this.#dirty = true
  }

  save(): void {
    if (this.#dirty) atomicWrite(this.#path, JSON.stringify(this.#marks), 0o600)
    this.#dirty = false
  }
}
