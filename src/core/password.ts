import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base32nopad } from '@scure/base'
import { argon2id } from 'hash-wasm'
import { z } from 'zod'

import { fromBase64, toBase64, utf8 } from './encoding'
import { TypeVaultError } from './errors'

const SECRET_KEY_PREFIX = 'TVSK'
const SECRET_KEY_BYTES = 20
const KDF = { memorySize: 65_536, iterations: 3, parallelism: 1 } as const

const SealedSchema = z.object({
  v: z.literal(1),
  kdf: z.object({
    name: z.literal('argon2id'),
    salt: z.string(),
    memorySize: z.number().int().positive(),
    iterations: z.number().int().positive(),
    parallelism: z.number().int().positive(),
  }),
  nonce: z.string(),
  ciphertext: z.string(),
})

export function generateSecretKeyCode(): string {
  const encoded = base32nopad.encode(crypto.getRandomValues(new Uint8Array(SECRET_KEY_BYTES)))
  return [SECRET_KEY_PREFIX, ...(encoded.match(/.{1,8}/g) ?? [])].join('-')
}

/**
 * Seals `plaintext` under a key derived from both the password and the Secret Key, like 1Password's two-secret
 * derivation: the sealed blob can sit in git, because guessing the password offline is useless without the Secret Key.
 */
export async function sealWithPassword(plaintext: Uint8Array, password: string, secretKey: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveKey(password, secretKey, salt, KDF)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, new Uint8Array(plaintext)),
  )
  const sealed: z.infer<typeof SealedSchema> = {
    v: 1,
    kdf: { name: 'argon2id', salt: toBase64(salt), ...KDF },
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
  }
  return `${JSON.stringify(sealed, null, 2)}\n`
}

/** Opens what `sealWithPassword` sealed; a wrong password or Secret Key is `denied`. */
export async function openWithPassword(sealed: string, password: string, secretKey: string): Promise<Uint8Array> {
  const parsed = SealedSchema.safeParse(parseJson(sealed))
  if (!parsed.success) throw new TypeVaultError('invalid', 'malformed sealed member key')
  const { kdf, nonce, ciphertext } = parsed.data
  const key = await deriveKey(password, secretKey, fromBase64(kdf.salt), kdf)
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(fromBase64(nonce)) },
        key,
        new Uint8Array(fromBase64(ciphertext)),
      ),
    )
  } catch (error) {
    if (error instanceof Error) throw new TypeVaultError('denied', 'wrong password or Secret Key')
    throw error
  }
}

async function deriveKey(
  password: string,
  secretKey: string,
  salt: Uint8Array,
  params: { readonly memorySize: number; readonly iterations: number; readonly parallelism: number },
): Promise<CryptoKey> {
  const stretched = await argon2id({
    password: password.normalize('NFKC'),
    salt,
    memorySize: params.memorySize,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: 32,
    outputType: 'binary',
  })
  const secret = parseSecretKeyCode(secretKey)
  const material = new Uint8Array([...stretched, ...secret])
  const raw = hkdf(sha256, material, salt, utf8('typevault member key'), 32)
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

function parseSecretKeyCode(text: string): Uint8Array {
  const [prefix, ...groups] = text.trim().toUpperCase().split('-')
  try {
    const bytes = prefix === SECRET_KEY_PREFIX ? base32nopad.decode(groups.join('')) : undefined
    if (bytes?.length === SECRET_KEY_BYTES) return bytes
  } catch (error) {
    if (!(error instanceof Error)) throw error
  }
  throw new TypeVaultError('invalid', 'not a TypeVault Secret Key (TVSK-...)')
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch (error) {
    if (error instanceof SyntaxError) return undefined
    throw error
  }
}
