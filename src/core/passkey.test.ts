import { describe, expect, it } from 'bun:test'

import { p256 as curve } from '@noble/curves/nist.js'

import { fromBase64Url, toBase64Url } from './encoding'
import { decodeBase64Url, isP256PrivateKey, isUserHandle } from './passkey'
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
