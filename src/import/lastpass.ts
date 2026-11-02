import { TypeVaultError } from '../core/errors'
import { csvRecords } from './csv-rows'
import { collectEntries } from './shared'
import type { ImportResult } from './types'

export function parseLastpass(text: string): ImportResult {
  const { headers, records } = csvRecords(text)
  if (!['url', 'username', 'password', 'extra', 'name', 'grouping'].every((key) => headers.includes(key))) {
    throw new TypeVaultError('invalid', 'invalid LastPass CSV header')
  }
  const warnings: string[] = []
  const items = records.flatMap((row) => {
    const extra = row['extra'] ?? ''
    // LastPass stores structured card/identity records inside the secure-note column.
    if (row['url'] === 'http://sn' && /^NoteType:(?!Generic(?:\r?\n|$))/.test(extra)) {
      warnings.push('skipped unsupported LastPass secure-note type')
      return []
    }
    const note = row['url'] === 'http://sn'
    return [
      {
        title: row['name'] ?? '',
        container: row['grouping'] ?? '',
        type: note ? ('note' as const) : ('password' as const),
        fields: note
          ? { text: extra }
          : { username: row['username'], password: row['password'], totp: row['totp'], url: row['url'] },
        ...(note || row['url'] === undefined ? {} : { url: row['url'] }),
      },
    ]
  })
  return collectEntries(items, warnings)
}
