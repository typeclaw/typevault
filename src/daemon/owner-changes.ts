import { randomToken } from '../core/crypto'
import { TypeVaultError } from '../core/errors'

/** Under Bun's 10-second idle timeout, which also cuts a request whose handler hasn't answered yet. */
export const OWNER_CHANGE_POLL_MS = 5_000
const KEEP_MS = 10 * 60_000

type Change<T> = { readonly owner: string; readonly done: Promise<T>; settledAt?: number }
export type Waited<T> = { readonly done: false } | { readonly done: true; readonly result: T }

/**
 * Owner changes through a session, one at a time, so each publishes its effects in commit order. A rotation can outlast
 * any one request, so a change is admitted at once and its outcome collected by polling, never lost with a connection.
 * Stopping admits nothing new, cancels what hasn't started and waits for the one running.
 */
export class OwnerChanges<T> {
  #tail: Promise<unknown> = Promise.resolve()
  #stopping = false
  readonly #changes = new Map<string, Change<T>>()

  admit(owner: string, run: () => Promise<T>): string {
    if (this.#stopping) throw new TypeVaultError('locked', 'this session is locking: nothing changed')
    const now = Date.now()
    for (const [id, change] of this.#changes) {
      if (change.settledAt !== undefined && change.settledAt + KEEP_MS <= now) this.#changes.delete(id)
    }
    const done = this.#tail.then(() => {
      if (this.#stopping)
        throw new TypeVaultError('locked', 'the session locked before this change started: nothing changed')
      return run()
    })
    const change: Change<T> = { owner, done }
    const settled = done.then(
      () => undefined,
      () => undefined,
    )
    void settled.then(() => {
      change.settledAt = Date.now()
    })
    this.#tail = settled
    const id = randomToken(16)
    this.#changes.set(id, change)
    return id
  }

  async wait(owner: string, id: string, waitMs: number): Promise<Waited<T>> {
    const change = this.#changes.get(id)
    if (change === undefined || change.owner !== owner) throw new TypeVaultError('not_found', 'no such owner change')
    const { promise: timedOut, resolve } = Promise.withResolvers<Waited<T>>()
    const timer = setTimeout(() => resolve({ done: false }), waitMs)
    try {
      const waited = await Promise.race([change.done.then((result) => ({ done: true as const, result })), timedOut])
      if (waited.done) this.#changes.delete(id)
      return waited
    } catch (error) {
      this.#changes.delete(id)
      throw error
    } finally {
      clearTimeout(timer)
    }
  }

  async stop(): Promise<void> {
    this.#stopping = true
    await this.#tail
  }
}
