import { expect, test } from 'bun:test'

import { utf8 } from './encoding'
import { parseEntryName, type Field } from './naming'
import { encodePayload, decodePayload, type EntryPayload } from './payload'

const payload: EntryPayload = {
  v: 1,
  name: parseEntryName('service'),
  fields: { $default: { type: 'secret', value: 'secret' } },
  tags: [],
  created: '2026-01-01T00:00:00.000Z',
  rotated: '2026-01-01T00:00:00.000Z',
}
test.each([
  { type: 'secret', value: 'secret' },
  { type: 'text', value: 'public' },
  { type: 'totp', value: 'SEED' },
  { type: 'oauth', value: { access_token: 'token', refresh_token: 'refresh' } },
] satisfies readonly Field[])('round trips a typed field %p', (field) => {
  const input = { ...payload, fields: { custom: field } }
  expect(decodePayload(encodePayload(input))).toEqual(input)
})
test.each([
  { type: 'secret', value: {} },
  { type: 'text', value: {} },
  { type: 'totp', value: {} },
  { type: 'oauth', value: 'token' },
  { type: 'oauth', value: { refresh_token: 'refresh' } },
  { type: 'oauth', value: { access_token: 42 } },
  { type: 'other', value: 'secret' },
  'old field',
])('rejects malformed field values as tampered: %p', (field) => {
  expect(() => decodePayload(utf8(JSON.stringify({ ...payload, fields: { custom: field } })))).toThrow(
    expect.objectContaining({ code: 'tampered' }),
  )
})
test('rejects the old entry-level type instead of migrating it', () => {
  expect(() => decodePayload(utf8(JSON.stringify({ ...payload, type: 'api_key' })))).toThrow(
    expect.objectContaining({ code: 'tampered' }),
  )
})
test('rejects reserved stored field names when encoding', () => {
  expect(() => encodePayload({ ...payload, fields: { $other: { type: 'secret', value: 'secret' } } })).toThrow(
    expect.objectContaining({ code: 'invalid' }),
  )
})
test.each(['PATH', 'CURL_HOME', 'SERVICE_PROXY'])('refuses the reserved override %s when encoding a write', (env) => {
  expect(() => encodePayload({ ...payload, env })).toThrow(expect.objectContaining({ code: 'invalid' }))
})
test.each(['lowercase', '1START', 'HAS-DASH', 'HAS=EQUALS'])('rejects malformed stored env syntax %s', (env) => {
  expect(() => decodePayload(utf8(JSON.stringify({ ...payload, env })))).toThrow(
    expect.objectContaining({ code: 'tampered' }),
  )
})
