import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { isFieldName, parseEntryName, slugifySegment, type EntryType } from '../core/naming'
import type { ImportedEntry, ImportResult } from './types'

export type ImportItem = {
  readonly title: string
  readonly container?: string
  readonly type: EntryType
  readonly fields: Readonly<Record<string, string | undefined>>
  readonly url?: string
  readonly tags?: readonly string[]
  readonly env?: string
}

export function collectEntries(items: readonly ImportItem[], warnings: readonly string[] = []): ImportResult {
  const entries: ImportedEntry[] = []
  const messages = [...warnings]
  const used = new Set<string>()
  for (const item of items) {
    const service = slugifySegment(item.title)
    const base = item.container ? `${service}/${slugifySegment(item.container)}` : service
    let name = base
    let suffix = 2
    while (used.has(name)) name = `${base}-${suffix++}`
    used.add(name)
    if (name !== base) messages.push(`name collision: "${base}" renamed to "${name}"`)
    const fields: Record<string, string> = {}
    for (const [field, value] of Object.entries(item.fields)) {
      if (value === undefined || value === '') continue
      if (isFieldName(field)) fields[field] = value
      else messages.push(`${name}: skipped a field with an unusable name`)
    }
    const url = item.url === undefined ? null : URL.parse(item.url)
    const origin = url && (url.protocol === 'http:' || url.protocol === 'https:') ? url.origin : undefined
    entries.push({
      name: parseEntryName(name),
      type: item.type,
      fields,
      tags: item.tags ?? [],
      ...(origin === undefined ? {} : { origin }),
      ...(item.env === undefined ? {} : { env: item.env }),
    })
  }
  return { entries, warnings: messages }
}

export function parseJson<T>(text: string, schema: z.ZodType<T>, format: string): T {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch (error) {
    if (error instanceof SyntaxError) throw new TypeVaultError('invalid', `invalid ${format} JSON`)
    throw error
  }
  return parseExternal(value, schema, format)
}

export function parseExternal<T>(value: unknown, schema: z.ZodType<T>, format: string): T {
  const parsed = schema.safeParse(value)
  if (!parsed.success) throw new TypeVaultError('invalid', `invalid ${format} data`)
  return parsed.data
}
