import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import {
  isFieldName,
  parseEntryName,
  slugifySegment,
  PRESETS,
  type Preset,
  type Field,
  type FieldType,
  fieldStrings,
} from '../core/naming'
import type { ImportedEntry, ImportResult } from './types'

export type ImportItem = {
  readonly title: string
  readonly container?: string
  readonly preset: Preset
  readonly fields: Readonly<Record<string, string | Field | undefined>>
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
    const fields: Record<string, Field> = {}
    for (const [field, value] of Object.entries(item.fields)) {
      if (
        value === undefined ||
        value === '' ||
        (typeof value !== 'string' && fieldStrings(value).every((part) => part === ''))
      )
        continue
      if (isFieldName(field)) {
        if (typeof value === 'string') {
          const types: Readonly<Record<string, FieldType>> = PRESETS[item.preset].fields
          const type = types[field] ?? 'secret'
          switch (type) {
            case 'secret':
            case 'text':
            case 'totp':
              fields[field] = { type, value }
              break
            case 'oauth':
              throw new TypeVaultError('invalid', 'OAuth import requires typed fields')
            default:
              throw new TypeVaultError('invalid', `unexpected field type ${type satisfies never}`)
          }
        } else fields[field] = value
      } else messages.push(`${name}: skipped a field with an unusable name`)
    }
    const url = item.url === undefined ? null : URL.parse(item.url)
    const origin = url && (url.protocol === 'http:' || url.protocol === 'https:') ? url.origin : undefined
    entries.push({
      name: parseEntryName(name),
      fields,
      tags: item.tags ?? [],
      ...(origin === undefined ? {} : { origin }),
      ...(item.env === undefined ? {} : { env: item.env }),
    })
  }
  return { entries, warnings: messages }
}

/**
 * The template fields plus every labeled field the mapper didn't place, kept under its own label. A value already
 * in a template field is skipped, so an API credential's `credential` doesn't land twice.
 */
export function withCustomFields(
  mapped: Readonly<Record<string, string | Field | undefined>>,
  labeled: readonly (readonly [label: string, value: string | Field | undefined])[],
): Record<string, string | Field | undefined> {
  const used = new Set(
    Object.values(mapped).flatMap((value) =>
      value === undefined ? [] : typeof value === 'string' ? [value] : fieldStrings(value),
    ),
  )
  const custom: Record<string, string | Field> = {}
  for (const [label, value] of labeled) {
    const field = label.trim()
    if (
      field === '' ||
      value === undefined ||
      value === '' ||
      (typeof value === 'string' ? used.has(value) : fieldStrings(value).every((part) => used.has(part)))
    )
      continue
    if (Object.hasOwn(mapped, field) || Object.hasOwn(custom, field)) continue
    custom[field] = value
  }
  return { ...custom, ...mapped }
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
