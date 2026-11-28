import { p256 } from '@noble/curves/nist.js'
import { hex } from '@scure/base'

import { fromBase64Url, toBase64Url } from './encoding'

// The AlgorithmIdentifier of an EC key on P-256: id-ecPublicKey, then prime256v1.
const P256_ALGORITHM = hex.decode('301306072a8648ce3d020106082a8648ce3d030107')
// The prime256v1 OID, as ECPrivateKey's optional parameters repeat it.
const P256_CURVE = hex.decode('06082a8648ce3d030107')

// Chrome DevTools restores a credential's signature counter only up to UINT32_MAX.
export const MAX_SIGN_COUNT = 4_294_967_295
// WebAuthn, and Chrome DevTools with it, caps a user handle at 64 bytes.
const MAX_USER_HANDLE_BYTES = 64

export function isUserHandle(text: string): boolean {
  const bytes = decodeBase64Url(text)
  return bytes !== undefined && bytes.length <= MAX_USER_HANDLE_BYTES
}

export function decodeBase64Url(text: string): Uint8Array | undefined {
  try {
    const bytes = fromBase64Url(text)
    return text !== '' && toBase64Url(bytes) === text ? bytes : undefined
  } catch {
    return undefined
  }
}

/**
 * True for a PKCS#8 ECDSA P-256 private key that Chromium's virtual authenticator imports: BoringSSL's parser reads
 * every field, so the whole structure is checked, not just the scalar. That is a 32-byte scalar in range, the curve
 * parameters if repeated, the public key if present (it must be the scalar's), and no bytes left over at any level.
 */
export function isP256PrivateKey(pkcs8: Uint8Array): boolean {
  const outer = tlv(pkcs8, 0)
  if (outer?.tag !== 0x30 || outer.next !== pkcs8.length) return false
  const version = tlv(pkcs8, outer.start)
  if (version?.tag !== 0x02 || !equal(pkcs8.subarray(version.start, version.next), [0x00])) return false
  const algorithm = tlv(pkcs8, version.next)
  if (algorithm?.tag !== 0x30 || !equal(pkcs8.subarray(version.next, algorithm.next), P256_ALGORITHM)) return false
  const wrapped = tlv(pkcs8, algorithm.next)
  if (wrapped?.tag !== 0x04 || wrapped.next !== outer.next) return false
  const ecKey = tlv(pkcs8, wrapped.start)
  if (ecKey?.tag !== 0x30 || ecKey.next !== wrapped.next) return false
  const ecVersion = tlv(pkcs8, ecKey.start)
  if (ecVersion?.tag !== 0x02 || !equal(pkcs8.subarray(ecVersion.start, ecVersion.next), [0x01])) return false
  const scalarField = tlv(pkcs8, ecVersion.next)
  if (scalarField?.tag !== 0x04 || scalarField.next - scalarField.start !== 32) return false
  const scalar = pkcs8.subarray(scalarField.start, scalarField.next)
  if (!p256.utils.isValidSecretKey(scalar)) return false
  let at = scalarField.next
  const parameters = tlv(pkcs8, at)
  if (at < ecKey.next && parameters?.tag === 0xa0) {
    if (!equal(pkcs8.subarray(parameters.start, parameters.next), P256_CURVE)) return false
    at = parameters.next
  }
  const publicKey = tlv(pkcs8, at)
  if (at < ecKey.next && publicKey?.tag === 0xa1) {
    const bits = tlv(pkcs8, publicKey.start)
    if (bits?.tag !== 0x03 || bits.next !== publicKey.next || pkcs8[bits.start] !== 0x00) return false
    if (!equal(pkcs8.subarray(bits.start + 1, bits.next), p256.getPublicKey(scalar, false))) return false
    at = publicKey.next
  }
  return at === ecKey.next
}

type Tlv = { readonly tag: number; readonly start: number; readonly next: number }

// One DER tag-length-value at `at`: the content runs from `start` to `next`. Lengths past 0xffff never occur here.
// DER, and BoringSSL with it, takes only the shortest length encoding, so a long form that fits a shorter one fails.
function tlv(bytes: Uint8Array, at: number): Tlv | undefined {
  const tag = bytes[at]
  const first = bytes[at + 1]
  if (tag === undefined || first === undefined) return undefined
  let length = first
  let start = at + 2
  if (first === 0x81 || first === 0x82) {
    const size = first - 0x80
    length = 0
    for (let i = 0; i < size; i++) {
      const byte = bytes[start + i]
      if (byte === undefined) return undefined
      length = length * 256 + byte
    }
    if (length < (size === 1 ? 0x80 : 0x100)) return undefined
    start += size
  } else if (first > 0x7f) return undefined
  const next = start + length
  return next > bytes.length ? undefined : { tag, start, next }
}

const equal = (bytes: Uint8Array, expected: ArrayLike<number>): boolean =>
  bytes.length === expected.length && bytes.every((byte, i) => byte === expected[i])
