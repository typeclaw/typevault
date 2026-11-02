import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { parseExternal } from './shared'

export function parseCsvRows(text: string): readonly (readonly string[])[] {
  const input = parseExternal(text, z.string(), 'CSV').replace(/^\uFEFF/, '')
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let state: 'start' | 'plain' | 'quoted' | 'closed' = 'start'
  const invalid = () => new TypeVaultError('invalid', 'invalid CSV quoting')
  for (let index = 0; index < input.length; index++) {
    const char = input[index]
    if (state === 'quoted') {
      if (char === '"') {
        if (input[index + 1] === '"') {
          field += '"'
          index++
        } else state = 'closed'
      } else field += char
      continue
    }
    if (char === ',') {
      row.push(field)
      field = ''
      state = 'start'
    } else if (char === '\r' || char === '\n') {
      row.push(field)
      rows.push(row)
      row = []
      field = ''
      state = 'start'
      if (char === '\r' && input[index + 1] === '\n') index++
    } else if (char === '"' && state === 'start') {
      state = 'quoted'
    } else {
      if (char === '"' || state === 'closed') throw invalid()
      field += char
      state = 'plain'
    }
  }
  if (state === 'quoted') throw invalid()
  if (row.length > 0 || state !== 'start' || field !== '') rows.push([...row, field])
  return parseExternal(rows, z.array(z.array(z.string()).readonly()).readonly(), 'CSV')
}

export function csvRecords(text: string): {
  readonly headers: readonly string[]
  readonly records: readonly Readonly<Record<string, string>>[]
} {
  const [header, ...rows] = parseCsvRows(text)
  if (header === undefined) throw new TypeVaultError('invalid', 'missing CSV header')
  const headers = header.map((field) => field.toLowerCase())
  if (new Set(headers).size !== headers.length) throw new TypeVaultError('invalid', 'duplicate CSV header')
  const records = rows
    .filter((row) => row.length !== 1 || row[0] !== '')
    .map((row) => {
      if (row.length !== headers.length) throw new TypeVaultError('invalid', 'CSV row does not match header')
      return Object.fromEntries(headers.map((key, index) => [key, row[index] ?? '']))
    })
  return { headers, records }
}
