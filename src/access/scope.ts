import { TypeVaultError } from '../core/errors'
import { type EntryName, matchesOnly } from '../core/naming'
import { reachesGroup, type VaultState } from '../core/state'

/** What one grant allows: entries in groups it reaches, optionally narrowed by name patterns. */
export type GrantScope = { readonly groups: readonly string[]; readonly only: readonly string[] }

/** A derived grant must satisfy its own scope and every ancestor's. Empty chain = direct mode, everything. */
export type ScopeChain = readonly GrantScope[]

export const allowsGroup = (chain: ScopeChain, state: VaultState, group: string): boolean =>
  chain.every((scope) => reachesGroup(state.groups, scope.groups, group))

export const allowsEntry = (chain: ScopeChain, state: VaultState, group: string, name: EntryName): boolean =>
  chain.every(
    (scope) =>
      reachesGroup(state.groups, scope.groups, group) && (scope.only.length === 0 || matchesOnly(name, scope.only)),
  )

const UNITS = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const

/** `90s`, `30m`, `1h`, `2d` to milliseconds. */
export function parseTtl(text: string): number {
  const match = /^(\d+)([smhd])$/.exec(text.trim())
  const unit = match?.[2]
  if (match === null || unit === undefined || !(unit in UNITS)) {
    throw new TypeVaultError('invalid', `invalid TTL "${text}" (use e.g. 90s, 30m, 1h, 2d)`)
  }
  const amount = Number(match[1])
  switch (unit) {
    case 's':
    case 'm':
    case 'h':
    case 'd':
      return amount * UNITS[unit]
    default:
      throw new TypeVaultError('invalid', `invalid TTL unit "${unit}"`)
  }
}
