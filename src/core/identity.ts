import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import {
  decodeSecretKey,
  encodeSecretKey,
  generateSecretKey,
  type PublicKey,
  publicKeyOf,
  type SecretKey,
} from './crypto'
import { fromBase64Url, fromUtf8, toBase64Url, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { assertNoSymlinks, atomicWrite } from './fsx'
import { type Layout, resolveRoot } from './layout'
import { generateSecretKeyCode, openWithPassword, sealWithPassword } from './password'
import { type MemberKind, parseMemberName } from './state'

type Env = Readonly<Record<string, string | undefined>>

/**
 * Who this device acts as, in every vault. A human's member key is sealed by their password and Secret Key; a
 * machine (CI, an agent host) has no one to type a password, so it holds its member key directly.
 */
export type Identity = PublicKey &
  (
    | {
        readonly v: 1
        readonly kind: 'human'
        readonly name: string
        readonly secretKey: string
        readonly sealedKey: string
      }
    | { readonly v: 1; readonly kind: 'machine'; readonly name: string; readonly key: string }
  )

export type MemberPublic = PublicKey & { readonly kind: MemberKind }

const PublicFields = { recipient: z.string(), signPublic: z.string() }
const IdentitySchema = z.discriminatedUnion('kind', [
  z.object({
    v: z.literal(1),
    kind: z.literal('human'),
    name: z.string(),
    secretKey: z.string(),
    sealedKey: z.string(),
    ...PublicFields,
  }),
  z.object({ v: z.literal(1), kind: z.literal('machine'), name: z.string(), key: z.string(), ...PublicFields }),
])
const MemberPublicSchema = z.object({
  kind: z.enum(['human', 'machine']),
  recipient: z.string().startsWith('age1'),
  signPublic: z.string(),
})
const PUBLIC_PREFIX = 'tvp1:'

export const identityPath = (env: Env): string => join(resolveRoot(env), 'identity.json')

export function readIdentity(env: Env): Identity | undefined {
  const path = identityPath(env)
  return existsSync(path) ? IdentitySchema.parse(JSON.parse(readFileSync(path, 'utf8'))) : undefined
}

export function writeIdentity(env: Env, identity: Identity): void {
  atomicWrite(identityPath(env), `${JSON.stringify(identity, null, 2)}\n`, 0o600)
}

export async function createIdentity(
  rawName: string,
  kind: MemberKind,
  password?: string,
): Promise<{ readonly identity: Identity; readonly key: SecretKey }> {
  const name = parseMemberName(rawName)
  const key = await generateSecretKey({ kind: 'member', name })
  const pub = await publicKeyOf(key)
  if (kind === 'machine') return { identity: { v: 1, kind, name, key: encodeSecretKey(key), ...pub }, key }
  if (password === undefined || password === '') throw new TypeVaultError('invalid', 'a human member needs a password')
  const secretKey = generateSecretKeyCode()
  const sealedKey = await sealMemberKey(key, password, secretKey)
  return { identity: { v: 1, kind, name, secretKey, sealedKey, ...pub }, key }
}

export const memberPublicOfIdentity = (identity: Identity): MemberPublic => ({
  kind: identity.kind,
  recipient: identity.recipient,
  signPublic: identity.signPublic,
})

/**
 * Where a person's sealed member key is committed in a vault. The vault comes from git, so a planted symlink here
 * must never steer a read or a write outside it (onto identity.json, say).
 */
export function sealedCopyPath(layout: Layout, name: string): string {
  const rel = join('members', `${parseMemberName(name)}.key`)
  assertNoSymlinks(layout.vault, rel)
  return join(layout.vault, rel)
}

export const sealMemberKey = (key: SecretKey, password: string, secretKey: string): Promise<string> =>
  sealWithPassword(utf8(encodeSecretKey(key)), password, secretKey)

/** The member key inside a sealed copy (an identity's, or the one committed in a vault's members/). */
export async function openMemberKey(sealedKey: string, password: string, secretKey: string): Promise<SecretKey> {
  const key = decodeSecretKey(fromUtf8(await openWithPassword(sealedKey, password, secretKey)))
  if (key.role.kind !== 'member') throw new TypeVaultError('invalid', 'the sealed key is not a member key')
  return key
}

export function unlockIdentity(identity: Identity, password?: string): Promise<SecretKey> {
  if (identity.kind === 'machine') return Promise.resolve(decodeSecretKey(identity.key))
  if (password === undefined) throw new TypeVaultError('locked', 'a password is needed to unlock this identity')
  return openMemberKey(identity.sealedKey, password, identity.secretKey)
}

export const encodeMemberPublic = (member: MemberPublic): string =>
  PUBLIC_PREFIX + toBase64Url(utf8(JSON.stringify(member)))

export function decodeMemberPublic(text: string): MemberPublic {
  const trimmed = text.trim()
  if (!trimmed.startsWith(PUBLIC_PREFIX)) throw new TypeVaultError('invalid', 'not a member public key (tvp1:...)')
  try {
    return MemberPublicSchema.parse(JSON.parse(fromUtf8(fromBase64Url(trimmed.slice(PUBLIC_PREFIX.length)))))
  } catch (error) {
    if (error instanceof Error) throw new TypeVaultError('invalid', 'malformed member public key')
    throw error
  }
}
