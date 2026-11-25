import { existsSync, lstatSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { type PublicKey, publicKeyOf, type SecretKey } from './crypto'
import { TypeVaultError } from './errors'
import { assertNoSymlinks } from './fsx'
import type { Layout } from './layout'
import { includersOf, type VaultState } from './model'
import {
  openWrap,
  ownerWrapPath as portableOwnerWrapPath,
  samePublic,
  type WrapHolder,
  wrapPath as portableWrapPath,
} from './wraps'

export type { WrapHolder } from './wraps'

/** {@link portableWrapPath} with this platform's separators, for paths joined onto the vault directory. */
export const wrapPath = (tier: string, gen: number, holder: WrapHolder): string =>
  join(...portableWrapPath(tier, gen, holder).split('/'))

export const ownerWrapPath = (member: string): string => join(...portableOwnerWrapPath(member).split('/'))

/** The member keys among `keys` that match a member listed in the owner-signed state. */
export async function heldMembers(
  state: VaultState,
  keys: readonly SecretKey[],
): Promise<readonly { readonly name: string; readonly key: SecretKey }[]> {
  const held = await Promise.all(
    keys.map(async (key) => {
      if (key.role.kind !== 'member') return []
      const member = state.members[key.role.name]
      return member !== undefined && samePublic(await publicKeyOf(key), member) ? [{ name: key.role.name, key }] : []
    }),
  )
  return held.flat()
}

/** The owner key, unwrapped through an owner member's key when the owner key itself isn't held. */
export async function unwrapOwner(
  layout: Layout,
  state: VaultState,
  keys: readonly SecretKey[],
): Promise<SecretKey | undefined> {
  const held = keys.find((key) => key.role.kind === 'owner')
  if (held !== undefined) {
    if (!samePublic(await publicKeyOf(held), state.owner))
      throw new TypeVaultError('denied', 'this owner key no longer owns the vault')
    return held
  }
  for (const { name, key } of await heldMembers(state, keys)) {
    if (state.members[name]?.owner !== true) continue
    const owner = await openSealedKey(layout, ownerWrapPath(name), key, state.owner)
    if (owner !== undefined) return owner
  }
  return undefined
}

/** Resolves tier keys from the keys this process holds, unwrapping along includes. */
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

  get owner(): SecretKey | undefined {
    return this.#keys.find((key) => key.role.kind === 'owner')
  }

  /** The current-generation key of `tier`, or undefined when no held key reaches it. */
  unlock(tier: string): Promise<SecretKey | undefined> {
    const cached = this.#cache.get(tier)
    if (cached !== undefined) return cached
    const pending = this.#resolve(tier)
    this.#cache.set(tier, pending)
    return pending
  }

  async reachableTiers(): Promise<ReadonlySet<string>> {
    const names = Object.keys(this.#state.tiers)
    const unlocked = await Promise.all(
      names.map(async (name) => ((await this.unlock(name)) === undefined ? [] : [name])),
    )
    return new Set(unlocked.flat())
  }

  async #resolve(tier: string): Promise<SecretKey | undefined> {
    const meta = this.#state.tiers[tier]
    if (meta === undefined) return undefined
    const held = this.#keys.find(
      (key) => key.role.kind === 'tier' && key.role.tier === tier && key.role.gen === meta.gen,
    )
    if (held !== undefined) return held
    const owner = this.owner
    if (owner !== undefined) {
      const key = await this.#openWrap(tier, meta.gen, { kind: 'owner' }, owner)
      if (key !== undefined) return key
    }
    for (const { name, key: memberKey } of await heldMembers(this.#state, this.#keys)) {
      if (this.#state.members[name]?.tiers.includes(tier) !== true) continue
      const key = await this.#openWrap(tier, meta.gen, { kind: 'member', name }, memberKey)
      if (key !== undefined) return key
    }
    for (const includer of includersOf(this.#state.tiers, tier)) {
      const includerGen = this.#state.tiers[includer]?.gen
      const includerKey = await this.unlock(includer)
      if (includerGen === undefined || includerKey === undefined) continue
      const key = await this.#openWrap(tier, meta.gen, { kind: 'tier', tier: includer, gen: includerGen }, includerKey)
      if (key !== undefined) return key
    }
    return undefined
  }

  async #openWrap(tier: string, gen: number, holder: WrapHolder, holderKey: SecretKey): Promise<SecretKey | undefined> {
    const expected = this.#state.tiers[tier]
    if (expected === undefined) return undefined
    return openSealedKey(this.#layout, wrapPath(tier, gen, holder), holderKey, expected)
  }
}

/** Opens the key sealed at `rel` in the vault directory, if that file exists. */
async function openSealedKey(
  layout: Layout,
  rel: string,
  holderKey: SecretKey,
  expected: PublicKey,
): Promise<SecretKey | undefined> {
  assertNoSymlinks(layout.vault, rel)
  const path = join(layout.vault, rel)
  if (!existsSync(path) || !lstatSync(path).isFile()) return undefined
  return openWrap(readFileSync(path), [holderKey.identity], expected)
}
