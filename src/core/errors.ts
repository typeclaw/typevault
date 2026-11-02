export type ErrorCode =
  | 'invalid'
  | 'not_found'
  | 'denied'
  | 'conflict'
  | 'tampered'
  | 'expired'
  | 'locked'
  | 'unavailable'

export class TypeVaultError extends Error {
  readonly code: ErrorCode

  constructor(code: ErrorCode, message: string) {
    super(message)
    this.name = 'TypeVaultError'
    this.code = code
  }
}
