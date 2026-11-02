import { expect, test } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { parseLastpass } from './lastpass'

test('LastPass maps logins and notes with grouping accounts, CSV escapes, and collision suffixes', () => {
  const result = parseLastpass(
    'url,username,password,totp,extra,name,grouping,fav\r\n' +
      'https://example.com/a,user@example.com,hunter2,SEED,,GitHub,Work,0\r\n' +
      'http://sn,,,,"line one\r\nsay ""hello""",GitHub,Work,0\r\n' +
      'ftp://example.com,,other,,,Personal,,0\r\n',
  )
  expect(result.entries.map((entry) => [entry.name, entry.type, entry.fields, entry.origin])).toEqual([
    [
      'github/work',
      'password',
      { username: 'user@example.com', password: 'hunter2', totp: 'SEED', url: 'https://example.com/a' },
      'https://example.com',
    ],
    ['github/work-2', 'note', { text: 'line one\r\nsay "hello"' }, undefined],
    ['personal', 'password', { password: 'other', url: 'ftp://example.com' }, undefined],
  ])
  expect(result.warnings).toHaveLength(1)
  expect(result.warnings[0]).toContain('"github/work"')
  expect(result.warnings[0]).toContain('"github/work-2"')
})

test('LastPass skips structured card records without exposing secret contents', () => {
  const result = parseLastpass(
    'url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,NoteType:Credit Card,Card,,0',
  )
  expect(result.entries).toEqual([])
  expect(result.warnings).toHaveLength(1)
  expect(result.warnings.join()).not.toContain('Credit Card')
})

test('LastPass rejects other CSV schemas', () => {
  expect(() => parseLastpass('name,url,username,password\nExample,,,hunter2')).toThrow(TypeVaultError)
})
