import { hex } from '@scure/base'
import { z } from 'zod'

import { toBase64Url } from '../core/encoding'
import { TypeVaultError } from '../core/errors'
import type { Field, Passkey } from '../core/naming'
import { decodeBase64Url, isP256PrivateKey, isUserHandle, MAX_SIGN_COUNT } from '../core/passkey'
import { collectEntries, parseExternal, parseJson, type ImportItem } from './shared'
import type { ImportResult } from './types'

const TextSchema = z.string().nullish()
const ItemSchema = z.object({
  id: TextSchema,
  type: z.number().int(),
  name: z.string(),
  notes: TextSchema,
  login: z
    .object({
      username: TextSchema,
      password: TextSchema,
      totp: TextSchema,
      uris: z.array(z.object({ uri: TextSchema })).nullish(),
      // Checked in the login branch, so a malformed passkey list costs only itself, not its login or the import.
      fido2Credentials: z.unknown().optional(),
    })
    .nullish(),
  sshKey: z.object({ privateKey: TextSchema, publicKey: TextSchema }).nullish(),
})
const ExportSchema = z.object({ items: z.array(ItemSchema) })
const CredentialSchema = z.object({
  credentialId: z.string(),
  keyAlgorithm: TextSchema,
  keyCurve: TextSchema,
  keyValue: z.string(),
  rpId: z.string(),
  userHandle: TextSchema,
  userName: TextSchema,
  counter: TextSchema,
  discoverable: TextSchema,
})

export function parseBitwarden(text: string): ImportResult {
  const raw = parseJson(text, z.object({ encrypted: z.boolean().optional() }).passthrough(), 'Bitwarden')
  if (raw.encrypted === true) {
    throw new TypeVaultError('invalid', 'encrypted Bitwarden exports are not supported; export unencrypted JSON')
  }
  const data = parseExternal(raw, ExportSchema, 'Bitwarden')
  const items: ImportItem[] = []
  const warnings: string[] = []
  for (const item of data.items) {
    const common = { title: item.name, ...(item.id ? { source: `bitwarden:${item.id}` } : {}) }
    switch (item.type) {
      case 1: {
        const url = item.login?.uris?.find((uri) => uri.uri)?.uri ?? undefined
        const passkeys: Record<string, Field> = {}
        const list = item.login?.fido2Credentials ?? []
        if (!Array.isArray(list)) warnings.push("skipped a Bitwarden login's passkeys: they are not a list")
        for (const raw of Array.isArray(list) ? list : []) {
          const credential = CredentialSchema.safeParse(raw)
          const value = credential.success ? passkeyOf(credential.data) : undefined
          if (value === undefined) {
            warnings.push('skipped a Bitwarden passkey that is not a usable P-256 key with a readable id')
            continue
          }
          const count = Object.keys(passkeys).length
          passkeys[count === 0 ? 'passkey' : `passkey_${count + 1}`] = { type: 'passkey', value }
        }
        items.push({
          ...common,
          preset: 'password',
          fields: {
            username: item.login?.username ?? undefined,
            password: item.login?.password ?? undefined,
            totp: item.login?.totp ?? undefined,
            url,
            ...passkeys,
          },
          ...(url === undefined ? {} : { url }),
        })
        break
      }
      case 2:
        items.push({ ...common, preset: 'note', fields: { $default: item.notes ?? undefined } })
        break
      case 5:
        items.push({
          ...common,
          preset: 'ssh',
          fields: {
            private_key: item.sshKey?.privateKey ?? undefined,
            public_key: item.sshKey?.publicKey ?? undefined,
          },
        })
        break
      default:
        warnings.push('skipped unsupported Bitwarden item type')
    }
  }
  return collectEntries(items, warnings)
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function passkeyOf(credential: z.infer<typeof CredentialSchema>): Passkey | undefined {
  if (credential.keyAlgorithm !== 'ECDSA' || credential.keyCurve !== 'P-256' || credential.rpId === '') return undefined
  const id = credentialIdOf(credential.credentialId)
  const key = base64url(credential.keyValue)
  if (id === undefined || key === undefined || !isP256PrivateKey(decodeBase64Url(key) ?? new Uint8Array()))
    return undefined
  const normalized = credential.userHandle ? base64url(credential.userHandle) : undefined
  const handle = normalized !== undefined && isUserHandle(normalized) ? normalized : undefined
  const discoverable = credential.discoverable === 'true'
  if ((credential.userHandle && handle === undefined) || (discoverable && handle === undefined)) return undefined
  // A counter Chrome can't restore makes the passkey unusable; resetting it would look like a cloned key to the site.
  const counter = credential.counter ? Number(credential.counter) : 0
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > MAX_SIGN_COUNT) return undefined
  return {
    rp_id: credential.rpId,
    credential_id: id,
    private_key: key,
    discoverable,
    ...(handle === undefined ? {} : { user_handle: handle }),
    ...(credential.userName ? { user_name: credential.userName } : {}),
    ...(counter > 0 ? { sign_count: counter } : {}),
  }
}

// Bitwarden keeps a credential id it generated as a GUID of the raw 16 bytes, and any other id as `b64.<base64url>`.
function credentialIdOf(id: string): string | undefined {
  if (id.startsWith('b64.')) return base64url(id.slice(4))
  return GUID.test(id) ? toBase64Url(hex.decode(id.replaceAll('-', '').toLowerCase())) : undefined
}

function base64url(text: string): string | undefined {
  const value = text.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
  return decodeBase64Url(value) === undefined ? undefined : value
}
