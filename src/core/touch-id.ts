import { p256 } from '@noble/curves/nist.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { z } from 'zod'

import { fromBase64, toBase64, utf8 } from './encoding'
import { TypeVaultError } from './errors'

type Env = Readonly<Record<string, string | undefined>>

/**
 * A secret sealed to a Secure Enclave key: an ephemeral P-256 key agrees a secret with the enclave key, and that
 * secret seals the plaintext. Opening it needs the enclave, so this Mac and a touch of an enrolled finger.
 */
export const TouchIdSealSchema = z.object({
  handle: z.string(),
  ephemeral: z.string(),
  nonce: z.string(),
  ciphertext: z.string(),
})
export type TouchIdSeal = z.infer<typeof TouchIdSealSchema>

/** The enclave side of the agreement: given the key's handle and the ephemeral public key, the shared x coordinate. */
export type EnclaveExchange = (handle: Uint8Array, ephemeral: Uint8Array) => Promise<Uint8Array>

export async function sealToEnclave(
  plaintext: Uint8Array,
  handle: Uint8Array,
  enclavePublic: Uint8Array,
): Promise<TouchIdSeal> {
  const secret = p256.utils.randomSecretKey()
  const ephemeral = p256.getPublicKey(secret, false)
  const key = await sealingKey(p256.getSharedSecret(secret, enclavePublic).slice(1), ephemeral)
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, new Uint8Array(plaintext)),
  )
  return {
    handle: toBase64(handle),
    ephemeral: toBase64(ephemeral),
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
  }
}

export async function openFromEnclave(seal: TouchIdSeal, exchange: EnclaveExchange): Promise<Uint8Array> {
  const ephemeral = fromBase64(seal.ephemeral)
  const key = await sealingKey(await exchange(fromBase64(seal.handle), ephemeral), ephemeral)
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(fromBase64(seal.nonce)) },
        key,
        new Uint8Array(fromBase64(seal.ciphertext)),
      ),
    )
  } catch (error) {
    if (error instanceof Error) throw new TypeVaultError('denied', 'the Touch ID copy of your key does not open')
    throw error
  }
}

/**
 * Seals `plaintext` to a new Touch ID key on this Mac, and opens it once with a touch before returning, so a sensor
 * or enclave that doesn't work shows up now rather than at the next unlock.
 */
export async function enableTouchId(env: Env, plaintext: Uint8Array): Promise<TouchIdSeal> {
  const { createEnclaveKey } = await import('./secure-enclave')
  const { handle, publicKey } = createEnclaveKey()
  const seal = await sealToEnclave(plaintext, handle, publicKey)
  const opened = await openWithTouchId(env, seal, 'turn on Touch ID unlock')
  if (toBase64(opened) !== toBase64(plaintext)) {
    throw new TypeVaultError('unavailable', 'Touch ID opened something else than what was sealed')
  }
  return seal
}

export async function openWithTouchId(env: Env, seal: TouchIdSeal, reason = 'unlock your vault'): Promise<Uint8Array> {
  const { exchangeWithEnclave } = await import('./secure-enclave')
  return openFromEnclave(seal, (handle, ephemeral) => exchangeWithEnclave(env, handle, ephemeral, reason))
}

function sealingKey(shared: Uint8Array, ephemeral: Uint8Array): Promise<CryptoKey> {
  const raw = hkdf(sha256, shared, ephemeral, utf8('typevault touch id'), 32)
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
}
