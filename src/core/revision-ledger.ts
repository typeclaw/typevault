/**
 * The highest revision seen per id. Every old revision stays validly signed wherever copies are kept (git history, a
 * replica, a cache), so a swap back to one is caught here, by the reader, rather than trusted.
 */
/** The mark of a deleted id: above every revision an envelope may carry, and refused whatever the revision. */
const TOMBSTONE = Number.MAX_SAFE_INTEGER

export class RevisionLedger {
  readonly #marks: Record<string, number>
  #dirty = false

  constructor(marks: Readonly<Record<string, number>> = {}) {
    this.#marks = { ...marks }
  }

  /** False when `rev` is older than a revision already seen for `id`, or `id` was deleted. */
  allows(id: string, rev: number): boolean {
    const mark = this.#marks[id] ?? 0
    return mark !== TOMBSTONE && rev >= mark
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

  /** Marks `id` deleted: anything carrying it again (say, restored from history) is refused. */
  tombstone(id: string): void {
    this.#marks[id] = TOMBSTONE
    this.#dirty = true
  }

  /** Whether marks changed since construction or the last `snapshot()`. */
  get dirty(): boolean {
    return this.#dirty
  }

  /** The marks to persist. `dirty` stays set until the caller confirms they were written with `saved()`. */
  snapshot(): Readonly<Record<string, number>> {
    return { ...this.#marks }
  }

  /** Records that the marks returned by the last `snapshot()` were persisted. */
  saved(): void {
    this.#dirty = false
  }
}
