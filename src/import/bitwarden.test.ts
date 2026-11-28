import { expect, test } from 'bun:test'

import { fromBase64Url, toBase64, toBase64Url } from '../core/encoding'
import { TypeVaultError } from '../core/errors'
import { generatePasskeyKey, malformedPasskeyKey } from '../core/passkey.harness'
import { parseBitwarden } from './bitwarden'

const KEY = await generatePasskeyKey()
const login = (name: string, fido2Credentials: readonly object[]) => ({
  type: 1,
  name,
  login: { username: 'user@example.com', fido2Credentials },
})

test('Bitwarden maps login, note, and SSH records, naming logins after their username', () => {
  const result = parseBitwarden(
    JSON.stringify({
      items: [
        {
          id: 'item-1',
          type: 1,
          name: 'GitHub',
          login: {
            username: 'user@example.com',
            password: 'hunter2',
            totp: 'SEED',
            uris: [{ uri: null }, { uri: 'https://example.com:8443/path?q=secret' }],
          },
          notes: 'not a password field',
        },
        { type: 2, name: 'GitHub', notes: 'private note' },
        { type: 5, name: 'Build Key', sshKey: { privateKey: 'fake-private', publicKey: 'fake-public' } },
        { type: 1, name: 'Local', login: { username: '', password: '', uris: [{ uri: 'ftp://example.com' }] } },
        { type: 3, name: 'Card', notes: 'hunter2' },
        { type: 4, name: 'Identity' },
      ],
    }),
  )
  expect(result.entries.map((entry) => [entry.name, entry.fields, entry.origin])).toEqual([
    [
      'github/user@example.com',
      {
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'hunter2' },
        totp: { type: 'totp', value: 'SEED' },
        url: { type: 'text', value: 'https://example.com:8443/path?q=secret' },
      },
      'https://example.com:8443',
    ],
    ['github', { $default: { type: 'secret', value: 'private note' } }, undefined],
    [
      'build-key',
      { private_key: { type: 'secret', value: 'fake-private' }, public_key: { type: 'text', value: 'fake-public' } },
      undefined,
    ],
    ['local', { url: { type: 'text', value: 'ftp://example.com' } }, undefined],
  ])
  expect(result.entries.map((entry) => entry.source)).toEqual(['bitwarden:item-1', undefined, undefined, undefined])
  expect(result.warnings).toHaveLength(2)
  expect(result.warnings.join()).not.toContain('hunter2')
})

test('Bitwarden imports a login passkey as a typed field, skipping keys it cannot sign with', () => {
  // given
  const credential = {
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: KEY,
    rpId: 'example.com',
    userHandle: 'dXNlcg',
    userName: 'user@example.com',
    counter: '7',
    discoverable: 'true',
  }

  // when
  const result = parseBitwarden(
    JSON.stringify({
      items: [
        login('Example', [{ ...credential, credentialId: '0f8e1a2b-3c4d-5e6f-8091-a2b3c4d5e6f7' }]),
        login('Other', [
          {
            ...credential,
            credentialId: 'b64.Y3JlZA',
            keyValue: toBase64(fromBase64Url(KEY)),
            counter: '0',
            discoverable: 'false',
          },
          { ...credential, credentialId: 'b64.b3RoZXI', keyCurve: 'P-384' },
        ]),
      ],
    }),
  )

  // then
  expect(result.entries.map((entry) => entry.fields['passkey'])).toEqual([
    {
      type: 'passkey',
      value: {
        rp_id: 'example.com',
        credential_id: 'D44aKzxNXm-AkaKzxNXm9w',
        private_key: KEY,
        discoverable: true,
        user_handle: 'dXNlcg',
        user_name: 'user@example.com',
        sign_count: 7,
      },
    },
    {
      type: 'passkey',
      value: {
        rp_id: 'example.com',
        credential_id: 'Y3JlZA',
        private_key: KEY,
        discoverable: false,
        user_handle: 'dXNlcg',
        user_name: 'user@example.com',
      },
    },
  ])
  expect(result.entries.map((entry) => Object.keys(entry.fields))).toEqual([
    ['username', 'passkey'],
    ['username', 'passkey'],
  ])
  expect(result.warnings).toHaveLength(1)
})

test('Bitwarden skips an unusable passkey on its own, keeping its login and the rest of the import', () => {
  // given
  const valid = {
    credentialId: 'b64.Y3JlZA',
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: KEY,
    rpId: 'example.com',
    userHandle: 'dXNlcg',
    counter: '0',
    discoverable: 'true',
  }

  // when
  const result = parseBitwarden(
    JSON.stringify({
      items: [
        login('Example', [
          { ...valid, credentialId: null, keyValue: null },
          { ...valid, credentialId: 'b64.bm9rZXk', keyValue: 'cHJpdmF0ZS1rZXk' },
          { ...valid, credentialId: 'b64.bm9oYW5kbGU', userHandle: null },
          { ...valid, credentialId: 'b64.bWFsZm9ybWVk', keyValue: malformedPasskeyKey() },
          valid,
        ]),
        { type: 1, name: 'Plain', login: { username: 'user@example.com', password: 'hunter2' } },
      ],
    }),
  )

  // then
  expect(result.entries.map((entry) => [String(entry.name), Object.keys(entry.fields)])).toEqual([
    ['example/user@example.com', ['username', 'passkey']],
    ['plain/user@example.com', ['username', 'password']],
  ])
  expect(result.entries[0]?.fields['passkey']).toMatchObject({ value: { credential_id: 'Y3JlZA' } })
  expect(result.warnings).toHaveLength(4)
})

test('Bitwarden reads a missing discoverable as false, and warns past a passkey list that is not a list', () => {
  // given
  const credential = {
    credentialId: 'b64.Y3JlZA',
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: KEY,
    rpId: 'example.com',
  }

  // when
  const result = parseBitwarden(
    JSON.stringify({
      items: [
        login('Example', [credential, { ...credential, credentialId: 'b64.bnVsbA', discoverable: null }]),
        login('Garbage', 'not a list' as unknown as readonly object[]),
      ],
    }),
  )

  // then
  expect(result.entries.map((entry) => [String(entry.name), Object.keys(entry.fields)])).toEqual([
    ['example/user@example.com', ['username', 'passkey', 'passkey_2']],
    ['garbage/user@example.com', ['username']],
  ])
  expect(result.entries[0]?.fields['passkey']).toMatchObject({ value: { discoverable: false } })
  expect(result.entries[0]?.fields['passkey_2']).toMatchObject({ value: { discoverable: false } })
  expect(result.warnings).toHaveLength(1)
})

test('Bitwarden keeps a counter up to UINT32_MAX and skips a passkey whose counter Chrome cannot restore', () => {
  // given
  const credential = { keyAlgorithm: 'ECDSA', keyCurve: 'P-256', keyValue: KEY, rpId: 'example.com' }

  // when
  const result = parseBitwarden(
    JSON.stringify({
      items: [
        login('Example', [
          { ...credential, credentialId: 'b64.bWF4', counter: '4294967295' },
          { ...credential, credentialId: 'b64.b3Zlcg', counter: '4294967296' },
        ]),
      ],
    }),
  )

  // then
  expect(Object.keys(result.entries[0]?.fields ?? {})).toEqual(['username', 'passkey'])
  expect(result.entries[0]?.fields['passkey']).toMatchObject({
    value: { credential_id: 'bWF4', sign_count: 4_294_967_295 },
  })
  expect(result.warnings).toHaveLength(1)
})

test('Bitwarden keeps a 64-byte user handle and skips only a passkey whose user handle Chrome cannot restore', () => {
  // given
  const credential = {
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: KEY,
    rpId: 'example.com',
    discoverable: 'true',
  }

  // when
  const result = parseBitwarden(
    JSON.stringify({
      items: [
        login('Example', [
          { ...credential, credentialId: 'b64.bG9uZw', userHandle: toBase64Url(new Uint8Array(65)) },
          { ...credential, credentialId: 'b64.Zml0cw', userHandle: toBase64Url(new Uint8Array(64)) },
        ]),
      ],
    }),
  )

  // then
  expect(Object.keys(result.entries[0]?.fields ?? {})).toEqual(['username', 'passkey'])
  expect(result.entries[0]?.fields['passkey']).toMatchObject({ value: { credential_id: 'Zml0cw' } })
  expect(result.warnings).toHaveLength(1)
})

test('Bitwarden rejects encrypted exports before interpreting encrypted payloads', () => {
  expect(() => parseBitwarden('{"encrypted":true,"data":"hunter2"}')).toThrow(
    new TypeVaultError('invalid', 'encrypted Bitwarden exports are not supported; export unencrypted JSON'),
  )
})

test.each(['{', '{}', '{"items":[{"type":"1","name":"Example"}]}', '{"encrypted":"true"}'])(
  'Bitwarden rejects malformed JSON and schema: %p',
  (input) => {
    expect(() => parseBitwarden(input)).toThrow(TypeVaultError)
  },
)
