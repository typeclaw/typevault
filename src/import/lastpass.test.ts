import { expect, test } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { parseLastpass } from './lastpass'

test('LastPass maps logins and notes with username accounts and CSV escapes', () => {
  const result = parseLastpass(
    'url,username,password,totp,extra,name,grouping,fav\r\n' +
      'https://example.com/a,user@example.com,hunter2,SEED,,GitHub,Work,0\r\n' +
      'http://sn,,,,"line one\r\nsay ""hello""",GitHub,Work,0\r\n' +
      'ftp://example.com,,other,,,Personal,,0\r\n',
  )
  expect(result.entries.map((entry) => [entry.name, entry.fields, entry.origin])).toEqual([
    [
      'github/user@example.com',
      {
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'hunter2' },
        totp: { type: 'totp', value: 'SEED' },
        url: { type: 'text', value: 'https://example.com/a' },
      },
      'https://example.com',
    ],
    ['github', { $default: { type: 'secret', value: 'line one\r\nsay "hello"' } }, undefined],
    [
      'personal',
      { password: { type: 'secret', value: 'other' }, url: { type: 'text', value: 'ftp://example.com' } },
      undefined,
    ],
  ])
  expect(result.warnings).toEqual([])
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
