import { z } from 'zod'

import { sha256Hex } from '../core/crypto'
import { utf8 } from '../core/encoding'
import { TypeVaultError } from '../core/errors'
import {
  isFieldName,
  type EntryName,
  parseEntryName,
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
  /** The item's id in its password manager (`bitwarden:<id>`), when the source has stable ids. */
  readonly source?: string
}

export function collectEntries(items: readonly ImportItem[], warnings: readonly string[] = []): ImportResult {
  const entries: ImportedEntry[] = []
  const messages = [...warnings]
  const used = new Set<string>()
  const containers = new Map<string, string>()
  // A folder (or a 1Password account and vault) whose name mixes scripts still keeps its entries apart, under a
  // stable stand-in, rather than taking down every item in it.
  const containerSegment = (raw: string): string => {
    const known = containers.get(raw)
    if (known !== undefined) return known
    let segment = toSegment(raw)
    if (segment !== '' && entryNameOf(segment) === undefined) {
      const standIn = sha256Hex(utf8(segment)).slice(0, 8)
      messages.push(`"${raw}" makes no usable name segment; its entries use "${standIn}"`)
      segment = standIn
    }
    containers.set(raw, segment)
    return segment
  }
  for (const item of items) {
    const title = toSegment(item.title)
    const container = containerSegment(item.container ?? '')
    // Collisions are checked on the canonical name, so two spellings of one name can't land on the same entry.
    const base = entryNameOf(container === '' ? title : `${title}/${container}`)
    if (base === undefined) {
      messages.push(`skipped "${item.title}": its title makes no usable entry name`)
      continue
    }
    let name: string = base
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
      ...(item.source === undefined ? {} : { source: item.source }),
      ...(item.env === undefined ? {} : { env: item.env }),
    })
  }
  return { entries, warnings: messages }
}

/** A title or folder as a name segment: lowercase, with each run of spaces and other punctuation one `-`. */
const toSegment = (raw: string): string =>
  raw
    .toLowerCase()
    .normalize('NFC')
    .replace(/[^\p{L}\p{M}\p{N}.@+]+/gu, '-')
    .replace(/[.-]*-[.-]*/g, '-')
    .replace(/\.{2,}/g, '.')
    .replace(/^[.-]+|[.-]+$/g, '')

function entryNameOf(name: string): EntryName | undefined {
  try {
    return parseEntryName(name)
  } catch (error) {
    if (error instanceof TypeVaultError) return undefined
    throw error
  }
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
