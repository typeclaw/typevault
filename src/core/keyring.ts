import { existsSync, lstatSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { decodeSecretKey, publicKeyOf, type SecretKey, unseal } from './crypto'
import { fromUtf8 } from './encoding'
import type { Layout } from './layout'
import { includersOf, type VaultState } from './state'

export type WrapHolder =
  | { readonly kind: 'operator' }
  | { readonly kind: 'group'; readonly group: string; readonly gen: number }

/** Vault-relative path of a group key sealed to a holder: the operator, or an including group's key. */
export const wrapPath = (group: string, gen: number, holder: WrapHolder): string =>
  join('groups', group, String(gen), holder.kind === 'operator' ? 'operator.age' : `${holder.group}.${holder.gen}.age`)

/** Resolves group keys from the keys this process holds, unwrapping along includes. */
export class Keyring {
  readonly #layout: Layout
  readonly #state: VaultState
  readonly #keys: readonly SecretKey[]
  readonly #cache = new Map<string, Promise<SecretKey | undefined>>()

  constructor(layout: Layout, state: VaultState, keys: readonly SecretKey[]) {
    this.#layout = layout
    this.#state = state
    this.#keys = keys
  }

  get operator(): SecretKey | undefined {
    return this.#keys.find((key) => key.role.kind === 'operator')
  }

  /** The current-generation key of `group`, or undefined when no held key reaches it. */
  unlock(group: string): Promise<SecretKey | undefined> {
    const cached = this.#cache.get(group)
    if (cached !== undefined) return cached
    const pending = this.#resolve(group)
    this.#cache.set(group, pending)
    return pending
  }

  async reachableGroups(): Promise<ReadonlySet<string>> {
    const names = Object.keys(this.#state.groups)
    const unlocked = await Promise.all(
      names.map(async (name) => ((await this.unlock(name)) === undefined ? [] : [name])),
    )
    return new Set(unlocked.flat())
  }

  async #resolve(group: string): Promise<SecretKey | undefined> {
    const meta = this.#state.groups[group]
    if (meta === undefined) return undefined
    const held = this.#keys.find(
      (key) => key.role.kind === 'group' && key.role.group === group && key.role.gen === meta.gen,
    )
    if (held !== undefined) return held
    const operator = this.operator
    if (operator !== undefined) {
      const key = await this.#openWrap(group, meta.gen, { kind: 'operator' }, operator)
      if (key !== undefined) return key
    }
    for (const includer of includersOf(this.#state.groups, group)) {
      const includerGen = this.#state.groups[includer]?.gen
      const includerKey = await this.unlock(includer)
      if (includerGen === undefined || includerKey === undefined) continue
      const key = await this.#openWrap(
        group,
        meta.gen,
        { kind: 'group', group: includer, gen: includerGen },
        includerKey,
      )
      if (key !== undefined) return key
    }
    return undefined
  }

  async #openWrap(
    group: string,
    gen: number,
    holder: WrapHolder,
    holderKey: SecretKey,
  ): Promise<SecretKey | undefined> {
    const path = join(this.#layout.vault, wrapPath(group, gen, holder))
    if (!existsSync(path) || !lstatSync(path).isFile()) return undefined
    const key = decodeSecretKey(fromUtf8(await unseal([holderKey.identity], readFileSync(path))))
    // A wrap that doesn't match the operator-signed public key is ignored rather than trusted.
    const expected = this.#state.groups[group]
    const actual = await publicKeyOf(key)
    return expected !== undefined &&
      actual.recipient === expected.recipient &&
      actual.signPublic === expected.signPublic
      ? key
      : undefined
  }
}
