import { expect, test } from 'bun:test'
import { generateKeyPairSync, type KeyObject } from 'node:crypto'

import { toBase64Url, utf8 } from './encoding'
import { parseEntryName, type Field } from './naming'
import { generatePasskeyKey, malformedPasskeyKey } from './passkey.harness'
import { encodePayload, decodePayload, type EntryPayload } from './payload'

const KEY = await generatePasskeyKey()
const pkcs8Of = (key: KeyObject): string => toBase64Url(key.export({ format: 'der', type: 'pkcs8' }))
const ED25519_KEY = pkcs8Of(generateKeyPairSync('ed25519').privateKey)
const RSA_KEY = pkcs8Of(generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey)
const passkey = { rp_id: 'example.com', credential_id: 'Y3JlZA', private_key: KEY, discoverable: false }

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
  { type: 'passkey', value: passkey },
  {
    type: 'passkey',
    value: { ...passkey, discoverable: true, user_handle: 'dXNlcg', user_name: 'bot@example.com', sign_count: 3 },
  },
  { type: 'passkey', value: { ...passkey, sign_count: 4_294_967_295 } },
  { type: 'passkey', value: { ...passkey, user_handle: toBase64Url(new Uint8Array(64)) } },
  { type: 'passkey', value: { ...passkey, private_key: ED25519_KEY } },
  { type: 'passkey', value: { ...passkey, private_key: RSA_KEY } },
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
  { type: 'passkey', value: { ...passkey, rp_id: undefined } },
  { type: 'passkey', value: { ...passkey, credential_id: 'Y3JlZA==' } },
  { type: 'passkey', value: { ...passkey, sign_count: -1 } },
  { type: 'passkey', value: { ...passkey, sign_count: 4_294_967_296 } },
  { type: 'passkey', value: { ...passkey, user_handle: toBase64Url(new Uint8Array(65)) } },
  { type: 'passkey', value: { ...passkey, extra: 'x' } },
  { type: 'passkey', value: { ...passkey, discoverable: undefined } },
  { type: 'passkey', value: { ...passkey, discoverable: true } },
  { type: 'passkey', value: { ...passkey, private_key: 'cHJpdmF0ZS1rZXk' } },
  { type: 'passkey', value: { ...passkey, private_key: await generatePasskeyKey('P-384') } },
  { type: 'passkey', value: { ...passkey, private_key: malformedPasskeyKey() } },
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
test('refuses to write a passkey whose key has a valid scalar but a field Chromium cannot read', () => {
  const field = { type: 'passkey', value: { ...passkey, private_key: malformedPasskeyKey() } } as const
  expect(() => encodePayload({ ...payload, fields: { passkey: field } })).toThrow(
    expect.objectContaining({ code: 'invalid' }),
  )
})
