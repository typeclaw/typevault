import { TypeVaultError } from '../core/errors'
import { csvRecords } from './csv-rows'
import { collectEntries } from './shared'
import type { ImportResult } from './types'

export function parseCsv(text: string): ImportResult {
  const { headers, records } = csvRecords(text)
  const title = headers.includes('name') ? 'name' : 'title'
  if (![title, 'url', 'username', 'password'].every((key) => headers.includes(key))) {
    throw new TypeVaultError('invalid', 'unknown password CSV header')
  }
  return collectEntries(
    records.map((row) => ({
      title: row[title] ?? '',
      preset: 'password',
      fields: { username: row['username'], password: row['password'], url: row['url'], totp: row['otpauth'] },
      ...(row['url'] === undefined ? {} : { url: row['url'] }),
    })),
  )
}
