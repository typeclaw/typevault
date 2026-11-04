export type ErrorCode =
  | 'invalid'
  | 'not_found'
  | 'denied'
  | 'conflict'
  | 'tampered'
  | 'expired'
  | 'locked'
  | 'unavailable'
  /** Another machine's daemon is using this vault's state directory. */
  | 'in_use'
  /** No vault at the given directory. */
  | 'no_vault'
  /** A vault is there, but the key given is not one of its members. */
  | 'not_member'

export class TypeVaultError extends Error {
  readonly code: ErrorCode

  constructor(code: ErrorCode, message: string) {
    super(message)
    this.name = 'TypeVaultError'
    this.code = code
  }
}
