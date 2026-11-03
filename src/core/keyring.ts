import { existsSync, lstatSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { decodeSecretKey, publicKeyOf, type SecretKey, unseal } from './crypto'
import { TypeVaultError } from './errors'
import { assertNoSymlinks } from './fsx'
import type { Layout } from './layout'
import { includersOf, type VaultState } from './state'

export type WrapHolder =
  | { readonly kind: 'owner' }
  | { readonly kind: 'tier'; readonly tier: string; readonly gen: number }

/** Vault-relative path of a tier key sealed to a holder: the owner, or an including tier's key. */
export const wrapPath = (tier: string, gen: number, holder: WrapHolder): string =>
  join('tiers', tier, String(gen), holder.kind === 'owner' ? 'owner.age' : `${holder.tier}.${holder.gen}.age`)

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
    const rel = wrapPath(tier, gen, holder)
    assertNoSymlinks(this.#layout.vault, rel)
    const path = join(this.#layout.vault, rel)
    if (!existsSync(path) || !lstatSync(path).isFile()) return undefined
    // Wrap files aren't signed and the owner's recipient is public, so a planted wrap must fail quietly.
    const key = await unseal([holderKey.identity], readFileSync(path))
      .then((bytes) => decodeSecretKey(new TextDecoder().decode(bytes)))
      .catch((error: unknown) => {
        if (error instanceof TypeVaultError) return undefined
        throw error
      })
    if (key === undefined) return undefined
    // A wrap that doesn't match the owner-signed public key is ignored rather than trusted.
    const expected = this.#state.tiers[tier]
    const actual = await publicKeyOf(key)
    return expected !== undefined &&
      actual.recipient === expected.recipient &&
      actual.signPublic === expected.signPublic
      ? key
      : undefined
  }
}
