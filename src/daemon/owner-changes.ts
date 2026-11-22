import { existsSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { atomicWrite, ensureDir } from '../core/fsx'
import { toCode } from './client'

/** Under Bun's 10-second idle timeout, which also cuts a request whose handler hasn't answered yet. */
export const OWNER_CHANGE_POLL_MS = 5_000
/** How long an outcome stays readable, and so how long admitting the same id again is recognized as a retry. */
export const OWNER_CHANGE_KEEP_MS = 10 * 60_000
export const OwnerChangeId = z.string().regex(/^[A-Za-z0-9_-]{22}$/, 'not an owner change id')

const Outcome = z.union([
  z.object({ result: z.unknown() }),
  z.object({ error: z.object({ code: z.string(), message: z.string() }) }),
])
type Outcome = z.infer<typeof Outcome>
export type Waited<T> = { readonly done: false } | { readonly done: true; readonly result: T }

const outcomesDir = (run: string): string => join(run, 'owner-changes')
const outcomePath = (run: string, id: string): string => join(outcomesDir(run), `${OwnerChangeId.parse(id)}.json`)

const missing = (error: unknown): boolean => error instanceof Error && 'code' in error && error.code === 'ENOENT'

/** Whether the receipt at `path` is past its window; one removed meanwhile counts as past it. */
function expired(path: string): boolean {
  try {
    return statSync(path).mtimeMs + OWNER_CHANGE_KEEP_MS <= Date.now()
  } catch (error) {
    if (missing(error)) return true
    throw error
  }
}

// Cleanup only: a receipt removed meanwhile is already gone, and one that can't be removed is refused on reads anyway.
function remove(path: string): void {
  try {
    rmSync(path)
  } catch (error) {
    if (!missing(error)) console.error('typevault daemon: removing an expired owner-change outcome failed', error)
  }
}

export function readOutcome<T>(run: string, id: string, schema: z.ZodType<T>): T | undefined {
  const path = outcomePath(run, id)
  if (!existsSync(path)) return undefined
  if (expired(path)) {
    remove(path)
    return undefined
  }
  const outcome = Outcome.parse(JSON.parse(readFileSync(path, 'utf8')))
  if ('error' in outcome) throw new TypeVaultError(toCode(outcome.error.code), outcome.error.message)
  return schema.parse(outcome.result)
}

/**
 * Owner changes through a session, one at a time, so each publishes its effects in commit order. A rotation can outlast
 * any one request, and the session itself, so a change is admitted at once under the caller's own random id, the
 * receipt it polls with, and its outcome is kept for a while: in memory, and in the run directory for a caller whose
 * daemon stopped meanwhile. Within that window, admitting an id again changes nothing, so a caller that lost the answer
 * can ask again; past it, the id is unknown.
 * Stopping admits nothing new, cancels what hasn't started and waits for the one running.
 */
export class OwnerChanges<T> {
  readonly #run: string
  readonly #schema: z.ZodType<T>
  #tail: Promise<unknown> = Promise.resolve()
  #stopping = false
  readonly #changes = new Map<string, { readonly done: Promise<T>; settledAt?: number }>()

  constructor(run: string, schema: z.ZodType<T>) {
    this.#run = run
    this.#schema = schema
    this.#prune()
  }

  has(id: string): boolean {
    const change = this.#change(id)
    if (change !== undefined) return true
    const path = outcomePath(this.#run, id)
    return existsSync(path) && !expired(path)
  }

  admit(id: string, run: () => Promise<T>): void {
    if (this.has(id)) return
    if (this.#stopping) throw new TypeVaultError('locked', 'this session is locking: nothing changed')
    this.#prune()
    const done = this.#tail.then(() => {
      if (this.#stopping)
        throw new TypeVaultError('locked', 'the session locked before this change started: nothing changed')
      return run()
    })
    this.#changes.set(id, { done })
    this.#tail = done.then(
      (result) => this.#keep(id, { result }),
      (error: unknown) => this.#keep(id, { error: outcomeError(error) }),
    )
  }

  async wait(id: string, waitMs: number): Promise<Waited<T>> {
    const done = this.#change(id)?.done
    if (done === undefined) {
      const result = readOutcome(this.#run, id, this.#schema)
      if (result === undefined) throw new TypeVaultError('not_found', 'no such owner change')
      return { done: true, result }
    }
    const { promise: timedOut, resolve } = Promise.withResolvers<Waited<T>>()
    const timer = setTimeout(() => resolve({ done: false }), waitMs)
    try {
      return await Promise.race([done.then((result) => ({ done: true as const, result })), timedOut])
    } finally {
      clearTimeout(timer)
    }
  }

  /** Closes admission at once; settles once the running change has finished and its outcome is kept. */
  stop(): Promise<void> {
    this.#stopping = true
    return this.#tail.then(() => undefined)
  }

  // The change has settled whatever happens here: a receipt that can't be written leaves it in memory only, and never
  // stops the next change or a drain.
  #change(id: string): { readonly done: Promise<T>; settledAt?: number } | undefined {
    const change = this.#changes.get(id)
    if (change?.settledAt !== undefined && change.settledAt + OWNER_CHANGE_KEEP_MS <= Date.now()) {
      this.#changes.delete(id)
      return undefined
    }
    return change
  }

  #keep(id: string, outcome: Outcome): void {
    const change = this.#changes.get(id)
    if (change !== undefined) change.settledAt = Date.now()
    setTimeout(() => this.#changes.delete(id), OWNER_CHANGE_KEEP_MS).unref()
    try {
      ensureDir(outcomesDir(this.#run), 0o700)
      atomicWrite(outcomePath(this.#run, id), JSON.stringify(outcome), 0o600)
    } catch (error) {
      console.error('typevault daemon: keeping the outcome of an owner change on disk failed', error)
    }
  }

  #prune(): void {
    const dir = outcomesDir(this.#run)
    let files: string[]
    try {
      files = existsSync(dir) && statSync(dir).isDirectory() ? readdirSync(dir) : []
    } catch (error) {
      console.error('typevault daemon: listing owner-change outcomes failed', error)
      return
    }
    for (const file of files) {
      const path = join(dir, file)
      try {
        if (expired(path)) remove(path)
      } catch (error) {
        console.error('typevault daemon: checking an owner-change outcome failed', error)
      }
    }
  }
}

function outcomeError(error: unknown): { code: string; message: string } {
  if (error instanceof TypeVaultError) return { code: error.code, message: error.message }
  // Unexpected failures stay out of outcomes, as out of responses: they may carry details an agent shouldn't see.
  console.error('typevault daemon: owner change failed', error)
  return { code: 'unavailable', message: 'internal daemon error' }
}
