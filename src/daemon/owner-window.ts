import { randomToken, verifySignature } from '../core/crypto'
import { utf8 } from '../core/encoding'
import { TypeVaultError } from '../core/errors'

export const OWNER_WINDOW_MS = 5 * 60_000
const CHALLENGE_TTL_MS = 5 * 60_000

export const ownerWindowMessage = (nonce: string): Uint8Array => utf8(`typevault owner window ${nonce}`)

/**
 * Agents run as the same user and can read the session token, so a session alone never makes owner changes: they go
 * through only within a few minutes of a proof, a challenge signed with the member's own key, which only an owner
 * command makes. It starts closed, so an unlock for reading opens nothing. A chain of owner commands asks once; an
 * agent can't open the window itself.
 */
export class OwnerWindow {
  #until = 0
  readonly #challenges = new Map<string, number>()

  get isOpen(): boolean {
    return Date.now() < this.#until
  }

  challenge(): string {
    const now = Date.now()
    for (const [nonce, exp] of this.#challenges) if (exp <= now) this.#challenges.delete(nonce)
    const nonce = randomToken(16)
    this.#challenges.set(nonce, now + CHALLENGE_TTL_MS)
    return nonce
  }

  /** Each challenge works once, so a captured proof can't reopen the window. */
  open(nonce: string, signature: string, signPublic: string): void {
    const exp = this.#challenges.get(nonce)
    this.#challenges.delete(nonce)
    if (exp === undefined || exp <= Date.now() || !verifySignature(signPublic, ownerWindowMessage(nonce), signature)) {
      throw new TypeVaultError('denied', 'that proof does not allow owner changes')
    }
    this.#until = Date.now() + OWNER_WINDOW_MS
  }
}
