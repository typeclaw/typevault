import { beforeEach, expect, it, mock } from 'bun:test'

import { p256 } from '@noble/curves/nist.js'

import { publicKeyOf } from './crypto'
import { createIdentity, sealMemberKeyForTouchId, unlockIdentityWithTouchId } from './identity'
import { type EnclaveExchange, openFromEnclave, sealToEnclave } from './touch-id'

const plaintext = new Uint8Array([1, 2, 3])

// The Mac's enclave and its Touch ID dialog, mocked: tests never raise the real dialog.
let enclaveSecret = p256.utils.randomSecretKey()
const touchReasons: string[] = []
mock.module('./secure-enclave', () => ({
  createEnclaveKey: () => {
    enclaveSecret = p256.utils.randomSecretKey()
    return { handle: new Uint8Array([7]), publicKey: p256.getPublicKey(enclaveSecret, false) }
  },
  exchangeWithEnclave: (_env: unknown, _handle: Uint8Array, ephemeral: Uint8Array, reason: string) => {
    touchReasons.push(reason)
    return Promise.resolve(p256.getSharedSecret(enclaveSecret, ephemeral).slice(1))
  },
}))

beforeEach(() => {
  touchReasons.length = 0
})

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

it('turning Touch ID on takes one touch, and the next touch opens the member key', async () => {
  const { identity, key } = await createIdentity('alice', 'human', 'pw')

  const seal = await sealMemberKeyForTouchId({}, key)
  const opened = await unlockIdentityWithTouchId({}, identity, seal)

  expect(await publicKeyOf(opened)).toEqual(await publicKeyOf(key))
  expect(touchReasons).toEqual(['turn on Touch ID unlock', 'unlock your vault'])
})

it("refuses a Touch ID copy of another member's key", async () => {
  const alice = await createIdentity('alice', 'human', 'pw')
  const bob = await createIdentity('bob', 'human', 'pw')
  const bobSeal = await sealMemberKeyForTouchId({}, bob.key)

  await expect(unlockIdentityWithTouchId({}, alice.identity, bobSeal)).rejects.toMatchObject({ code: 'tampered' })
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
