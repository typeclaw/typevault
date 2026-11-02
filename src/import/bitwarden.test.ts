import { expect, test } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { parseBitwarden } from './bitwarden'

test('Bitwarden maps login, note, and SSH records with folder accounts and collision warnings', () => {
  const result = parseBitwarden(
    JSON.stringify({
      folders: [{ id: 'folder-1', name: 'Work / Team' }],
      items: [
        {
          type: 1,
          name: 'GitHub',
          folderId: 'folder-1',
          login: {
            username: 'user@example.com',
            password: 'hunter2',
            totp: 'SEED',
            uris: [{ uri: null }, { uri: 'https://example.com:8443/path?q=secret' }],
          },
          notes: 'not a password field',
        },
        { type: 2, name: 'GitHub', folderId: 'folder-1', notes: 'private note' },
        { type: 5, name: 'Build Key', sshKey: { privateKey: 'fake-private', publicKey: 'fake-public' } },
        { type: 1, name: 'Local', login: { username: '', password: '', uris: [{ uri: 'ftp://example.com' }] } },
        { type: 3, name: 'Card', notes: 'hunter2' },
        { type: 4, name: 'Identity' },
      ],
    }),
  )
  expect(result.entries.map((entry) => [entry.name, entry.type, entry.fields, entry.origin])).toEqual([
    [
      'github/work-team',
      'password',
      {
        username: 'user@example.com',
        password: 'hunter2',
        totp: 'SEED',
        url: 'https://example.com:8443/path?q=secret',
      },
      'https://example.com:8443',
    ],
    ['github/work-team-2', 'note', { text: 'private note' }, undefined],
    ['build-key', 'ssh', { private_key: 'fake-private', public_key: 'fake-public' }, undefined],
    ['local', 'password', { url: 'ftp://example.com' }, undefined],
  ])
  expect(result.warnings).toHaveLength(3)
  expect(result.warnings.join()).toContain('"github/work-team"')
  expect(result.warnings.join()).toContain('"github/work-team-2"')
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
