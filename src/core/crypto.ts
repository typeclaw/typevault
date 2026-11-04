import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from 'age-encryption'
import { z } from 'zod'

import { fromBase64, fromBase64Url, fromUtf8, toBase64, toBase64Url, utf8 } from './encoding'
import { TypeVaultError } from './errors'

export type KeyRole =
  | { readonly kind: 'owner' }
  | { readonly kind: 'tier'; readonly tier: string; readonly gen: number }
  | { readonly kind: 'member'; readonly name: string }

/** An age identity for decryption plus an Ed25519 key for signing. */
export type SecretKey = { readonly role: KeyRole; readonly identity: string; readonly signSecret: Uint8Array }
export type PublicKey = { readonly recipient: string; readonly signPublic: string }

const KEY_PREFIX = 'tvk1:'

const RoleSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('owner') }),
  z.object({ kind: z.literal('tier'), tier: z.string(), gen: z.number().int().positive() }),
  z.object({ kind: z.literal('member'), name: z.string() }),
])
const EncodedKeySchema = z.object({ role: RoleSchema, age: z.string().startsWith('AGE-SECRET-KEY-1'), ed: z.string() })

export async function generateSecretKey(role: KeyRole): Promise<SecretKey> {
  return { role, identity: await generateX25519Identity(), signSecret: ed25519.utils.randomSecretKey() }
}

export async function publicKeyOf(key: SecretKey): Promise<PublicKey> {
  return {
    recipient: await identityToRecipient(key.identity),
    signPublic: toBase64(ed25519.getPublicKey(key.signSecret)),
  }
}

export const encodeSecretKey = (key: SecretKey): string =>
  KEY_PREFIX + toBase64Url(utf8(JSON.stringify({ role: key.role, age: key.identity, ed: toBase64(key.signSecret) })))

export function decodeSecretKey(text: string): SecretKey {
  const trimmed = text.trim()
  if (!trimmed.startsWith(KEY_PREFIX)) throw new TypeVaultError('invalid', 'not a typevault key')
  let raw: unknown
  try {
    raw = JSON.parse(fromUtf8(fromBase64Url(trimmed.slice(KEY_PREFIX.length))))
  } catch (error) {
    if (error instanceof Error) {
      throw new TypeVaultError('invalid', 'malformed typevault key')
    }
    throw error
  }
  const parsed = EncodedKeySchema.safeParse(raw)
  if (!parsed.success) throw new TypeVaultError('invalid', 'malformed typevault key')
  const signSecret = fromBase64(parsed.data.ed)
  if (signSecret.length !== 32) throw new TypeVaultError('invalid', 'malformed typevault signing key')
  return { role: parsed.data.role, identity: parsed.data.age, signSecret }
}

export async function seal(recipients: readonly string[], plaintext: Uint8Array): Promise<Uint8Array> {
  const encrypter = new Encrypter()
  for (const recipient of recipients) encrypter.addRecipient(recipient)
  return encrypter.encrypt(plaintext)
}

/** Decrypts with the first matching identity; a ciphertext none of them can open is `denied`. */
export async function unseal(identities: readonly string[], ciphertext: Uint8Array): Promise<Uint8Array> {
  const decrypter = new Decrypter()
  for (const identity of identities) decrypter.addIdentity(identity)
  try {
    return await decrypter.decrypt(ciphertext)
  } catch (error) {
    if (error instanceof Error) throw new TypeVaultError('denied', `cannot decrypt: ${error.message}`)
    throw error
  }
}

/** A bare Ed25519 key pair, e.g. for a sealed grant's write certificate. */
export function generateSigningKey(): { readonly signSecret: Uint8Array; readonly signPublic: string } {
  const signSecret = ed25519.utils.randomSecretKey()
  return { signSecret, signPublic: toBase64(ed25519.getPublicKey(signSecret)) }
}

export const sign = (signSecret: Uint8Array, message: Uint8Array): string => toBase64(ed25519.sign(message, signSecret))

export function verifySignature(signPublic: string, message: Uint8Array, signature: string): boolean {
  try {
    return ed25519.verify(fromBase64(signature), message, fromBase64(signPublic))
  } catch (error) {
    if (error instanceof Error) return false
    throw error
  }
}

export const sha256Hex = (data: Uint8Array): string => bytesToHex(sha256(data))
export const randomHex = (bytes: number): string => bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)))
export const randomToken = (bytes: number): string => toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)))
