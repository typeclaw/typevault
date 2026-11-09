import { expect, it } from 'bun:test'

import { p256 } from '@noble/curves/nist.js'

import { type EnclaveExchange, openFromEnclave, sealToEnclave } from './touch-id'

const plaintext = new Uint8Array([1, 2, 3])

// A software P-256 key in place of the enclave: the same ECDH, returning the shared x coordinate.
function softwareEnclave(): { readonly publicKey: Uint8Array; readonly exchange: EnclaveExchange } {
  const secret = p256.utils.randomSecretKey()
  return {
    publicKey: p256.getPublicKey(secret, false),
    exchange: (_handle, ephemeral) => Promise.resolve(p256.getSharedSecret(secret, ephemeral).slice(1)),
  }
}

it('opens what was sealed to the enclave key, and keeps its handle', async () => {
  const enclave = softwareEnclave()
  const handle = new Uint8Array([9, 9])
  const seen: Uint8Array[] = []
  const sealed = await sealToEnclave(plaintext, handle, enclave.publicKey)

  const opened = await openFromEnclave(sealed, (given, ephemeral) => {
    seen.push(given)
    return enclave.exchange(given, ephemeral)
  })

  expect(opened).toEqual(plaintext)
  expect(seen).toEqual([handle])
})

it('refuses another enclave key and a changed ciphertext', async () => {
  const enclave = softwareEnclave()
  const sealed = await sealToEnclave(plaintext, new Uint8Array(1), enclave.publicKey)
  const flipped = Buffer.from(sealed.ciphertext, 'base64')
  flipped[0] = (flipped[0] ?? 0) ^ 1

  await expect(openFromEnclave(sealed, softwareEnclave().exchange)).rejects.toMatchObject({ code: 'denied' })
  await expect(
    openFromEnclave({ ...sealed, ciphertext: flipped.toString('base64') }, enclave.exchange),
  ).rejects.toMatchObject({ code: 'denied' })
})
