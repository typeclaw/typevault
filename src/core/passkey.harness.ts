import { p256 } from '@noble/curves/nist.js'

import { toBase64Url } from './encoding'

export async function generatePasskeyKey(namedCurve: 'P-256' | 'P-384' = 'P-256'): Promise<string> {
  const { privateKey } = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign'])
  return toBase64Url(new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey)))
}

const P256_ALGORITHM = [
  0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
  0x01, 0x07,
]
export const P256_PARAMETERS = der(0xa0, [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])

// `longForm` writes a length that fits one byte in the 0x81 form, which DER forbids.
export function der(tag: number, content: ArrayLike<number>, longForm = false): Uint8Array {
  const bytes = Array.from(content)
  const length = bytes.length < 0x80 && !longForm ? [bytes.length] : [0x81, bytes.length]
  return new Uint8Array([tag, ...length, ...bytes])
}

export function publicKeyField(point: Uint8Array, longForm = false): Uint8Array {
  return der(0xa1, der(0x03, [0x00, ...point]), longForm)
}

export function pkcs8Of(secret: Uint8Array, extras: readonly Uint8Array[] = []): Uint8Array {
  const ecKey = der(0x30, [0x02, 0x01, 0x01, ...der(0x04, secret), ...extras.flatMap((extra) => [...extra])])
  return der(0x30, [0x02, 0x01, 0x00, ...P256_ALGORITHM, ...der(0x04, ecKey)])
}

// A key with a valid scalar and its own public key, but in a field Chromium's DER reader refuses.
export function malformedPasskeyKey(): string {
  const scalar = p256.utils.randomSecretKey()
  return toBase64Url(pkcs8Of(scalar, [publicKeyField(p256.getPublicKey(scalar, false), true)]))
}
