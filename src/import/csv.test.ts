import { expect, test } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { parseCsv } from './csv'
import { parseCsvRows } from './csv-rows'

test('RFC 4180 handles escaped quotes, commas, CRLF, embedded newlines, and trailing empty fields', () => {
  expect(parseCsvRows('a,b,c\r\n"one,two","say ""hello""\r\nagain",\r\n')).toEqual([
    ['a', 'b', 'c'],
    ['one,two', 'say "hello"\r\nagain', ''],
  ])
})

test.each(['a,"unterminated', 'a,b"c', '"a"junk,b'])('CSV rejects invalid quoting: %p', (text) => {
  expect(() => parseCsvRows(text)).toThrow(TypeVaultError)
})

test('Chrome CSV maps logins and preserves passwords while deriving safe origins', () => {
  const result = parseCsv(
    '\uFEFFNAME,URL,USERNAME,PASSWORD,note\r\nGitHub,https://example.com:8443/path,user@example.com,hunter2,ignored\r\n' +
      'GitHub,ftp://example.com,user@example.com,second,\r\nGitHub-2,invalid,,,',
  )
  expect(result.entries.map((entry) => [entry.name, entry.fields, entry.origin])).toEqual([
    [
      'github',
      {
        url: { type: 'text', value: 'https://example.com:8443/path' },
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'hunter2' },
      },
      'https://example.com:8443',
    ],
    [
      'github-2',
      {
        url: { type: 'text', value: 'ftp://example.com' },
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'second' },
      },
      undefined,
    ],
    ['github-2-2', { url: { type: 'text', value: 'invalid' } }, undefined],
  ])
  expect(result.warnings).toHaveLength(2)
  expect(result.warnings[0]).toContain('"github"')
  expect(result.warnings[0]).toContain('"github-2"')
})

test('Safari CSV retains OTPAuth but excludes notes outside password field allowlist', () => {
  const result = parseCsv(
    'Title,URL,Username,Password,Notes,OTPAuth\nExample,https://example.com/a,,hunter2,private,otpauth://totp/Example?secret=SEED',
  )
  expect(result.entries[0]?.fields).toEqual({
    url: { type: 'text', value: 'https://example.com/a' },
    password: { type: 'secret', value: 'hunter2' },
    totp: { type: 'totp', value: 'otpauth://totp/Example?secret=SEED' },
  })
})

test.each(['', 'foo,bar\na,b', 'name,url,username,password\nshort,row', 'name,name,url,username,password'])(
  'CSV rejects missing or ambiguous headers and ragged records: %p',
  (text) => {
    expect(() => parseCsv(text)).toThrow(TypeVaultError)
  },
)
