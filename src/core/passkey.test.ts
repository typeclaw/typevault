import { describe, expect, it } from 'bun:test'
import { generateKeyPairSync, type KeyObject } from 'node:crypto'

import { p256 as curve } from '@noble/curves/nist.js'

import { fromBase64Url, toBase64Url } from './encoding'
import { decodeBase64Url, isP256PrivateKey, isPasskeyPrivateKey, isUserHandle } from './passkey'
import { der, generatePasskeyKey, P256_PARAMETERS, pkcs8Of, publicKeyField } from './passkey.harness'

const p256 = fromBase64Url(await generatePasskeyKey())
const p384 = fromBase64Url(await generatePasskeyKey('P-384'))
const scalar = curve.utils.randomSecretKey()
const publicKey = curve.getPublicKey(scalar, false)
const otherPublic = curve.getPublicKey(curve.utils.randomSecretKey(), false)

describe('isP256PrivateKey', () => {
  it('accepts a PKCS#8 P-256 key as WebCrypto exports it', () => {
    expect(isP256PrivateKey(p256)).toBe(true)
  })

  it.each([
    ['with neither parameters nor public key', pkcs8Of(scalar)],
    ['with the curve parameters and its own public key', pkcs8Of(scalar, [P256_PARAMETERS, publicKeyField(publicKey)])],
  ])('accepts a P-256 key %s', (_, bytes) => {
    expect(isP256PrivateKey(bytes)).toBe(true)
  })

  it.each([
    ['a P-384 key', p384],
    ['bytes that are no key', crypto.getRandomValues(new Uint8Array(32))],
    ['a truncated key', p256.subarray(0, p256.length - 10)],
    ['a key with trailing bytes', new Uint8Array([...p256, 0])],
    ['a zero scalar', withScalar(p256, new Uint8Array(32))],
    ["a public key that is not the scalar's", pkcs8Of(scalar, [publicKeyField(otherPublic)])],
    [
      'a public key not in its uncompressed form',
      pkcs8Of(scalar, [publicKeyField(new Uint8Array([0x05, ...publicKey.subarray(1)]))]),
    ],
    ['parameters for another curve', pkcs8Of(scalar, [der(0xa0, [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22])])],
    ['bytes left over in the EC key', pkcs8Of(scalar, [new Uint8Array([0x05, 0x00])])],
    [
      'a public key field with a longer length encoding than DER allows',
      pkcs8Of(scalar, [publicKeyField(publicKey, true)]),
    ],
  ])('refuses %s', (_, bytes) => {
    expect(isP256PrivateKey(bytes)).toBe(false)
  })
})

const RSA_HEADER = [
  0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
]

describe('isPasskeyPrivateKey', () => {
  const pkcs8 = (key: KeyObject) => new Uint8Array(key.export({ format: 'der', type: 'pkcs8' }))
  const ed25519 = pkcs8(generateKeyPairSync('ed25519').privateKey)
  const rsaKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
  const rsa = pkcs8(rsaKey)
  // DER with a two-byte length, which an RSA key's structures need.
  const long = (tag: number, content: Uint8Array): Uint8Array =>
    new Uint8Array([tag, 0x82, content.length >> 8, content.length & 0xff, ...content])
  // The version and rsaEncryption AlgorithmIdentifier, then an RSAPrivateKey of the given numbers.
  const rsaPkcs8 = (numbers: Uint8Array): Uint8Array =>
    long(0x30, new Uint8Array([...RSA_HEADER, ...long(0x04, long(0x30, numbers))]))
  const numbers = new Uint8Array(rsaKey.export({ format: 'der', type: 'pkcs1' })).subarray(4)
  const rsaRebuilt = rsaPkcs8(numbers)
  const rsaWithExtraNumber = rsaPkcs8(new Uint8Array([...numbers, 0x02, 0x01, 0x01]))
  // An RSA key from its numbers, so a test can pick numbers that agree with one another but break one of BoringSSL's
  // bounds.
  const jwk = rsaKey.export({ format: 'jwk' })
  const big = (field: string | undefined): bigint =>
    BigInt(`0x${Buffer.from(field ?? '', 'base64url').toString('hex')}`)
  const [n, d, p, q] = [big(jwk.n), big(jwk.d), big(jwk.p), big(jwk.q)]
  const integer = (value: bigint): number[] => {
    let digits = value.toString(16)
    if (digits.length % 2 === 1) digits = `0${digits}`
    if (Number.parseInt(digits.slice(0, 2), 16) >= 0x80) digits = `00${digits}`
    const bytes = [...Buffer.from(digits, 'hex')]
    const length =
      bytes.length < 0x80
        ? [bytes.length]
        : bytes.length < 0x100
          ? [0x81, bytes.length]
          : [0x82, bytes.length >> 8, bytes.length & 0xff]
    return [0x02, ...length, ...bytes]
  }
  const inverse = (value: bigint, modulus: bigint): bigint => {
    let [a, b, x, y] = [value % modulus, modulus, 1n, 0n]
    while (b !== 0n) {
      const k = a / b
      ;[a, b, x, y] = [b, a - k * b, y, x - k * y]
    }
    return ((x % modulus) + modulus) % modulus
  }
  const rsaOf = (e: bigint, privateExponent: bigint): Uint8Array =>
    rsaPkcs8(
      new Uint8Array(
        [
          0n,
          n,
          e,
          privateExponent,
          p,
          q,
          privateExponent % (p - 1n),
          privateExponent % (q - 1n),
          inverse(q, p),
        ].flatMap(integer),
      ),
    )
  const phi = (p - 1n) * (q - 1n)
  const gcd = (a: bigint, b: bigint): bigint => (b === 0n ? a : gcd(b, a % b))
  // A 35-bit exponent with an inverse modulo φ, so only the 33-bit bound can refuse the key it builds.
  let wideExponent = (1n << 34n) + 1n
  while (gcd(wideExponent, phi) !== 1n) wideExponent += 2n
  const rsaRebuiltFromNumbers = rsaOf(big(jwk.e), d)

  it.each([
    ['a P-256 key', p256],
    ['an Ed25519 key', ed25519],
    ['an RSA key', rsa],
  ])('accepts %s, as Chromium creates for ES256, EdDSA and RS256', (_, bytes) => {
    expect(isPasskeyPrivateKey(bytes)).toBe(true)
  })

  it('accepts the RSA keys this test rebuilds, so each malformed rebuild below differs only by what it breaks', () => {
    expect(isPasskeyPrivateKey(rsaRebuilt)).toBe(true)
    expect(isPasskeyPrivateKey(rsaRebuiltFromNumbers)).toBe(true)
  })

  it.each([
    ['a P-384 key', p384],
    ['an X25519 key', pkcs8(generateKeyPairSync('x25519').privateKey)],
    ['a truncated Ed25519 key', ed25519.subarray(0, ed25519.length - 1)],
    ['an Ed25519 key with trailing bytes', new Uint8Array([...ed25519, 0])],
    ['an RSA key with trailing bytes', new Uint8Array([...rsa, 0])],
    ['a truncated RSA key', rsa.subarray(0, rsa.length - 10)],
    ['an RSA key with a number after its eight', rsaWithExtraNumber],
    ['an RSA key whose private exponent, though consistent, is not below the modulus', rsaOf(big(jwk.e), d + 2n * phi)],
    ['an RSA key with a public exponent of more than 33 bits', rsaOf(wideExponent, inverse(wideExponent, phi))],
    ['an RSA key whose numbers disagree', new Uint8Array([...rsa.subarray(0, -1), (rsa.at(-1) ?? 0) ^ 0x01])],
  ])('refuses %s', (_, bytes) => {
    expect(isPasskeyPrivateKey(bytes)).toBe(false)
  })
})

describe('isUserHandle', () => {
  it('accepts a handle of up to 64 bytes and refuses 65', () => {
    expect(isUserHandle(toBase64Url(new Uint8Array(64)))).toBe(true)
    expect(isUserHandle(toBase64Url(new Uint8Array(65)))).toBe(false)
  })
})

describe('decodeBase64Url', () => {
  it('decodes canonical base64url', () => {
    expect(decodeBase64Url(toBase64Url(p256))).toEqual(p256)
  })

  it.each(['', 'Y3JlZA==', 'a+/b', 'Y3JlZB', 'not base64!'])('refuses %p', (text) => {
    expect(decodeBase64Url(text)).toBeUndefined()
  })
})

// The scalar is the 32 bytes after `04 20` inside the ECPrivateKey.
function withScalar(pkcs8: Uint8Array, value: Uint8Array): Uint8Array {
  const copy = new Uint8Array(pkcs8)
  const at = copy.findIndex((byte, i) => byte === 0x04 && copy[i + 1] === 0x20 && i > 30)
  copy.set(value, at + 2)
  return copy
}
