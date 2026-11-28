import { p256 } from '@noble/curves/nist.js'
import { hex } from '@scure/base'

import { fromBase64Url, toBase64Url } from './encoding'

// The AlgorithmIdentifier of an EC key on P-256: id-ecPublicKey, then prime256v1.
const P256_ALGORITHM = hex.decode('301306072a8648ce3d020106082a8648ce3d030107')
// The prime256v1 OID, as ECPrivateKey's optional parameters repeat it.
const P256_CURVE = hex.decode('06082a8648ce3d030107')

// An Ed25519 key in PKCS#8 as RFC 8410 and Chromium write it: version 0, id-Ed25519, then the 32-byte seed.
const ED25519_PREFIX = hex.decode('302e020100300506032b657004220420')
// The AlgorithmIdentifier of an RSA key: rsaEncryption, then NULL parameters.
const RSA_ALGORITHM = hex.decode('300d06092a864886f70d0101010500')
// BoringSSL, which Chromium's virtual authenticator imports keys with, takes RSA moduli of 512 to 16384 bits and
// public exponents of at most 33 bits.
const MIN_RSA_BITS = 512
const MAX_RSA_BITS = 16_384
const MAX_RSA_EXPONENT_BITS = 33

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
 * True for a private key Chromium's virtual authenticator creates and imports: ES256 (P-256), EdDSA (Ed25519) or
 * RS256 (RSA), each in PKCS#8. A site picks the algorithm, so a passkey may hold any of the three.
 */
export function isPasskeyPrivateKey(pkcs8: Uint8Array): boolean {
  return isP256PrivateKey(pkcs8) || isEd25519PrivateKey(pkcs8) || isRsaPrivateKey(pkcs8)
}

function isEd25519PrivateKey(pkcs8: Uint8Array): boolean {
  return pkcs8.length === ED25519_PREFIX.length + 32 && equal(pkcs8.subarray(0, ED25519_PREFIX.length), ED25519_PREFIX)
}

// A two-prime RSA key in DER as Chromium's BoringSSL imports it: rsaEncryption with NULL parameters, then an
// RSAPrivateKey of version 0 and eight minimal positive integers, nothing left over, and numbers that agree with one
// another the way BoringSSL's own key check requires. Pure, so the browser prompt page can bundle it.
function isRsaPrivateKey(pkcs8: Uint8Array): boolean {
  const outer = tlv(pkcs8, 0)
  if (outer?.tag !== 0x30 || outer.next !== pkcs8.length) return false
  const version = tlv(pkcs8, outer.start)
  if (version?.tag !== 0x02 || !equal(pkcs8.subarray(version.start, version.next), [0x00])) return false
  const algorithm = tlv(pkcs8, version.next)
  if (algorithm?.tag !== 0x30 || !equal(pkcs8.subarray(version.next, algorithm.next), RSA_ALGORITHM)) return false
  const wrapped = tlv(pkcs8, algorithm.next)
  if (wrapped?.tag !== 0x04 || wrapped.next !== outer.next) return false
  const rsaKey = tlv(pkcs8, wrapped.start)
  if (rsaKey?.tag !== 0x30 || rsaKey.next !== wrapped.next) return false
  const numbers: bigint[] = []
  let at = rsaKey.start
  for (let i = 0; i < 9; i++) {
    const field = tlv(pkcs8, at)
    if (field?.tag !== 0x02 || field.next > rsaKey.next) return false
    const value = positiveInteger(pkcs8.subarray(field.start, field.next), i === 0)
    if (value === undefined) return false
    numbers.push(value)
    at = field.next
  }
  if (at !== rsaKey.next) return false
  const [keyVersion, n, e, d, p, q, dp, dq, qi] = numbers as [
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
  ]
  const bits = n.toString(2).length
  if (keyVersion !== 0n || bits < MIN_RSA_BITS || bits > MAX_RSA_BITS || n % 2n === 0n) return false
  if (e.toString(2).length > MAX_RSA_EXPONENT_BITS || d >= n) return false
  if (p <= 1n || q <= 1n || p * q !== n || e < 3n || e % 2n === 0n) return false
  return (
    (e * d) % (p - 1n) === 1n % (p - 1n) &&
    (e * d) % (q - 1n) === 1n % (q - 1n) &&
    dp === d % (p - 1n) &&
    dq === d % (q - 1n) &&
    qi < p &&
    (qi * q) % p === 1n
  )
}

// A DER INTEGER's content as a non-negative number: minimal (no needless leading zero byte) and not negative. Only the
// version may be zero.
function positiveInteger(content: Uint8Array, mayBeZero: boolean): bigint | undefined {
  const first = content[0]
  if (first === undefined || first >= 0x80) return undefined
  if (first === 0x00 && content.length > 1 && (content[1] ?? 0) < 0x80) return undefined
  const value = BigInt(`0x${hex.encode(content)}`)
  return value === 0n && !mayBeZero ? undefined : value
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
