import { strFromU8, unzipSync } from 'fflate'
import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { collectEntries, parseExternal, parseJson, withCustomFields, type ImportItem } from './shared'
import type { ImportResult } from './types'

const KeySchema = z.object({
  privateKey: z.string().optional(),
  publicKey: z.string().optional(),
  metadata: z.object({ privateKey: z.string().optional(), publicKey: z.string().optional() }).optional(),
})
const FieldSchema = z.object({
  id: z.string().default(''),
  title: z.string().default(''),
  value: z.object({
    string: z.string().optional(),
    concealed: z.string().optional(),
    totp: z.string().optional(),
    sshKey: KeySchema.optional(),
  }),
})
const ItemSchema = z.object({
  categoryUuid: z.string(),
  state: z.string().optional(),
  overview: z.object({ title: z.string(), url: z.string().optional(), tags: z.array(z.string()).default([]) }),
  details: z.object({
    loginFields: z.array(z.object({ designation: z.string().optional(), value: z.string() })).default([]),
    sections: z.array(z.object({ fields: z.array(FieldSchema).default([]) })).default([]),
    notesPlain: z.string().default(''),
  }),
})
const ExportSchema = z.object({
  accounts: z.array(
    z.object({
      vaults: z.array(
        z.object({
          attrs: z.object({ name: z.string().optional() }).optional(),
          name: z.string().optional(),
          items: z.array(ItemSchema),
        }),
      ),
    }),
  ),
})

export function parse1Password(bytes: Uint8Array): ImportResult {
  parseExternal(bytes, z.instanceof(Uint8Array), '1PUX')
  let files: ReturnType<typeof unzipSync>
  try {
    files = unzipSync(bytes, { filter: (file) => file.name === 'export.data' })
  } catch (error) {
    if (error instanceof Error) throw new TypeVaultError('invalid', 'invalid 1PUX archive')
    throw error
  }
  const data = files['export.data']
  if (data === undefined) throw new TypeVaultError('invalid', '1PUX archive is missing export.data')
  const exported = parseJson(strFromU8(data), ExportSchema, '1PUX')
  const items: ImportItem[] = []
  const warnings: string[] = []
  for (const account of exported.accounts) {
    for (const vault of account.vaults) {
      for (const item of vault.items) {
        if (item.state === 'archived') continue
        const mapped = mapItem(item)
        if (mapped === undefined) {
          warnings.push('skipped unsupported 1Password item category')
          continue
        }
        const container = vault.attrs?.name ?? vault.name
        items.push({
          ...mapped,
          title: item.overview.title,
          tags: item.overview.tags,
          ...(container === undefined ? {} : { container }),
          ...(item.overview.url === undefined ? {} : { url: item.overview.url }),
        })
      }
    }
  }
  return collectEntries(items, warnings)
}

function mapItem(item: z.infer<typeof ItemSchema>): Omit<ImportItem, 'title'> | undefined {
  const mapped = mapTemplate(item)
  if (mapped === undefined) return undefined
  const labeled = item.details.sections
    .flatMap((section) => section.fields)
    .map(
      (field) =>
        [
          field.title,
          field.value.concealed !== undefined
            ? { type: 'secret' as const, value: field.value.concealed }
            : field.value.totp !== undefined
              ? { type: 'totp' as const, value: field.value.totp }
              : field.value.string === undefined
                ? undefined
                : { type: 'text' as const, value: field.value.string },
        ] as const,
    )
  return { ...mapped, fields: withCustomFields(mapped.fields, labeled) }
}

function mapTemplate(item: z.infer<typeof ItemSchema>): Omit<ImportItem, 'title'> | undefined {
  const sections = item.details.sections.flatMap((section) => section.fields)
  const field = (names: readonly string[]) =>
    sections.find((value) => names.includes(value.id.toLowerCase()) || names.includes(value.title.toLowerCase()))
  const text = (names: readonly string[]) => {
    const value = field(names)?.value
    return value?.concealed ?? value?.string
  }
  switch (item.categoryUuid) {
    case '001':
    case '005':
      return {
        preset: 'password',
        fields: {
          username:
            item.details.loginFields.find((value) => value.designation === 'username')?.value ?? text(['username']),
          password:
            item.details.loginFields.find((value) => value.designation === 'password')?.value ?? text(['password']),
          totp: sections.find((value) => value.value.totp !== undefined)?.value.totp,
          url: item.overview.url,
        },
      }
    case '003':
      return { preset: 'note', fields: { $default: item.details.notesPlain } }
    case '112':
      return { preset: 'api_key', fields: { $default: text(['credential', 'api key', 'api_key', 'key']) } }
    case '114': {
      const key = sections.find((value) => value.value.sshKey !== undefined)?.value.sshKey
      return {
        preset: 'ssh',
        fields: {
          private_key: key?.metadata?.privateKey ?? key?.privateKey ?? text(['private_key', 'private key']),
          public_key: key?.publicKey ?? key?.metadata?.publicKey ?? text(['public_key', 'public key']),
        },
      }
    }
    default:
      return undefined
  }
}
