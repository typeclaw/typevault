import { expect, test } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { parseBitwarden } from './bitwarden'

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
