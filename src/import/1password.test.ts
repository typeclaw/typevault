import { expect, test } from 'bun:test'

import { strToU8, zipSync } from 'fflate'

import { TypeVaultError } from '../core/errors'
import { parse1Password } from './1password'

function archive(items: readonly unknown[], vault = 'Work'): Uint8Array {
  return zipSync({
    'export.data': strToU8(JSON.stringify({ accounts: [{ vaults: [{ attrs: { name: vault }, items }] }] })),
  })
}

function item(categoryUuid: string, details: Readonly<Record<string, unknown>> = {}, title = 'GitHub') {
  return {
    categoryUuid,
    overview: { title, url: 'https://example.com/path?secret=hidden', tags: ['work', 'agent'] },
    details: { loginFields: [], sections: [], notesPlain: '', ...details },
  }
}

test('1PUX maps login, password, secure note, API, SSH, and tags without unsupported fields', () => {
  const result = parse1Password(
    archive([
      item('001', {
        loginFields: [
          { designation: 'username', value: 'user@example.com' },
          { designation: 'password', value: 'hunter2' },
        ],
        sections: [{ fields: [{ id: 'otp', value: { totp: 'otpauth://totp/Example?secret=SEED' } }] }],
      }),
      item('005', { sections: [{ fields: [{ id: 'password', value: { concealed: 'second' } }] }] }),
      item('003', { notesPlain: 'private note' }, 'Memo'),
      item(
        '112',
        {
          sections: [
            {
              fields: [
                { id: 'credential', value: { concealed: 'fake-key' } },
                { id: 'custom1', title: 'Webhook Secret', value: { concealed: 'whsec' } },
                { id: 'custom2', title: 'Valid From', value: { date: 1700000000 } },
              ],
            },
          ],
        },
        'API',
      ),
      item(
        '114',
        {
          sections: [
            {
              fields: [
                { id: 'private_key', value: { sshKey: { privateKey: 'fake-private', publicKey: 'fake-public' } } },
              ],
            },
          ],
        },
        'SSH',
      ),
      item('002'),
      item('004'),
      { ...item('001'), state: 'archived' },
    ]),
  )
  expect(result.entries.map((entry) => [String(entry.name), entry.fields])).toEqual([
    [
      'github/user@example.com',
      {
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'hunter2' },
        url: { type: 'text', value: 'https://example.com/path?secret=hidden' },
        totp: { type: 'totp', value: 'otpauth://totp/Example?secret=SEED' },
      },
    ],
    [
      'github',
      {
        password: { type: 'secret', value: 'second' },
        url: { type: 'text', value: 'https://example.com/path?secret=hidden' },
      },
    ],
    ['memo', { $default: { type: 'secret', value: 'private note' } }],
    ['api', { $default: { type: 'secret', value: 'fake-key' }, 'Webhook Secret': { type: 'secret', value: 'whsec' } }],
    [
      'ssh',
      { private_key: { type: 'secret', value: 'fake-private' }, public_key: { type: 'text', value: 'fake-public' } },
    ],
  ])
  expect(result.entries[0]?.origin).toBe('https://example.com')
  expect(result.entries[0]?.tags).toEqual(['work', 'agent'])
  expect(result.warnings).toHaveLength(2)
  expect(result.warnings.join()).not.toContain('hunter2')
})

test('1PUX ignores non-web origins', () => {
  const record = { ...item('001'), overview: { title: 'GitHub', url: 'javascript:alert(1)' } }
  const bytes = zipSync({ 'export.data': strToU8(JSON.stringify({ accounts: [{ vaults: [{ items: [record] }] }] })) })
  const result = parse1Password(bytes)
  expect<string | undefined>(result.entries[0]?.name).toBe('github')
  expect(result.entries[0]?.origin).toBeUndefined()
  expect(result.entries[0]?.fields).toEqual({ url: { type: 'text', value: 'javascript:alert(1)' } })
})

test.each([
  new Uint8Array([0, 1, 2]),
  zipSync({ other: strToU8('{}') }),
  zipSync({ 'export.data': strToU8('{') }),
  zipSync({ 'export.data': strToU8('{"accounts":[]}') }).slice(0, 8),
  zipSync({ 'export.data': strToU8('{}') }),
])('1PUX rejects malformed archives, absent export.data, and invalid JSON schemas', (bytes) => {
  expect(() => parse1Password(bytes)).toThrow(TypeVaultError)
})
