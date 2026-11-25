import {
  decodeSecretKey,
  encodeSecretKey,
  type Identity,
  type PublicKey,
  publicKeyOf,
  seal,
  type SecretKey,
  unseal,
} from './crypto'
import { fromUtf8, utf8 } from './encoding'

export type WrapHolder =
  | { readonly kind: 'owner' }
  | { readonly kind: 'tier'; readonly tier: string; readonly gen: number }
  | { readonly kind: 'member'; readonly name: string }

/** Vault-relative path (always `/`-separated) of a tier key sealed to a holder: the owner, an including tier, a member. */
export function wrapPath(tier: string, gen: number, holder: WrapHolder): string {
  const dir = `tiers/${tier}/${gen}`
  switch (holder.kind) {
    case 'owner':
      return `${dir}/owner.age`
    case 'tier':
      return `${dir}/${holder.tier}.${holder.gen}.age`
    case 'member':
      return `${dir}/members/${holder.name}.age`
  }
}

export const ownerWrapPath = (member: string): string => `owner/${member}.age`

export const samePublic = (a: PublicKey, b: PublicKey): boolean =>
  a.recipient === b.recipient && a.signPublic === b.signPublic

export const sealWrap = (key: SecretKey, recipients: readonly string[]): Promise<Uint8Array> =>
  seal(recipients, utf8(encodeSecretKey(key)))

/**
 * Opens a sealed key, keeping it only when it matches the public key it should be. Wraps aren't signed and recipients
 * are public, so a planted or foreign wrap yields undefined instead of an error.
 */
export async function openWrap(
  sealed: Uint8Array,
  holders: readonly Identity[],
  expected: PublicKey,
): Promise<SecretKey | undefined> {
  let key: SecretKey
  try {
    key = decodeSecretKey(fromUtf8(await unseal(holders, sealed)))
    // An identity that only looks like one (the decoder checks its prefix) fails here, inside the same guard.
    return samePublic(await publicKeyOf(key), expected) ? key : undefined
  } catch (error) {
    // Not ours, not UTF-8, not a key: every way a planted or corrupt wrap can fail lets the caller try the next one.
    if (error instanceof Error) return undefined
    throw error
  }
}
