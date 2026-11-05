import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { collectEntries, parseExternal, parseJson, type ImportItem } from './shared'
import type { ImportResult } from './types'

const TextSchema = z.string().nullish()
const ItemSchema = z.object({
  id: TextSchema,
  type: z.number().int(),
  name: z.string(),
  folderId: TextSchema,
  notes: TextSchema,
  login: z
    .object({
      username: TextSchema,
      password: TextSchema,
      totp: TextSchema,
      uris: z.array(z.object({ uri: TextSchema })).nullish(),
    })
    .nullish(),
  sshKey: z.object({ privateKey: TextSchema, publicKey: TextSchema }).nullish(),
})
const ExportSchema = z.object({
  folders: z.array(z.object({ id: z.string(), name: z.string() })).default([]),
  items: z.array(ItemSchema),
})

export function parseBitwarden(text: string): ImportResult {
  const raw = parseJson(text, z.object({ encrypted: z.boolean().optional() }).passthrough(), 'Bitwarden')
  if (raw.encrypted === true) {
    throw new TypeVaultError('invalid', 'encrypted Bitwarden exports are not supported; export unencrypted JSON')
  }
  const data = parseExternal(raw, ExportSchema, 'Bitwarden')
  const folders = new Map(data.folders.map((folder) => [folder.id, folder.name]))
  const items: ImportItem[] = []
  const warnings: string[] = []
  for (const item of data.items) {
    const container = item.folderId ? folders.get(item.folderId) : undefined
    const common = {
      title: item.name,
      ...(container === undefined ? {} : { container }),
      ...(item.id ? { source: `bitwarden:${item.id}` } : {}),
    }
    switch (item.type) {
      case 1: {
        const url = item.login?.uris?.find((uri) => uri.uri)?.uri ?? undefined
        items.push({
          ...common,
          preset: 'password',
          fields: {
            username: item.login?.username ?? undefined,
            password: item.login?.password ?? undefined,
            totp: item.login?.totp ?? undefined,
            url,
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
