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
  expect(result.entries.map((entry) => [String(entry.name), entry.type, entry.fields])).toEqual([
    [
      'github/work',
      'password',
      {
        username: 'user@example.com',
        password: 'hunter2',
        url: 'https://example.com/path?secret=hidden',
        totp: 'otpauth://totp/Example?secret=SEED',
      },
    ],
    ['github/work-2', 'password', { password: 'second', url: 'https://example.com/path?secret=hidden' }],
    ['memo/work', 'note', { text: 'private note' }],
    ['api/work', 'api_key', { key: 'fake-key', 'Webhook Secret': 'whsec' }],
    ['ssh/work', 'ssh', { private_key: 'fake-private', public_key: 'fake-public' }],
  ])
  expect(result.entries[0]?.origin).toBe('https://example.com')
  expect(result.entries[0]?.tags).toEqual(['work', 'agent'])
  expect(result.warnings).toHaveLength(3)
  expect(result.warnings.join()).toContain('"github/work"')
  expect(result.warnings.join()).toContain('"github/work-2"')
  expect(result.warnings.join()).not.toContain('hunter2')
})

test('1PUX omits missing containers and ignores non-web origins', () => {
  const record = { ...item('001'), overview: { title: 'GitHub', url: 'javascript:alert(1)' } }
  const bytes = zipSync({ 'export.data': strToU8(JSON.stringify({ accounts: [{ vaults: [{ items: [record] }] }] })) })
  const result = parse1Password(bytes)
  expect<string | undefined>(result.entries[0]?.name).toBe('github')
  expect(result.entries[0]?.origin).toBeUndefined()
  expect(result.entries[0]?.fields).toEqual({ url: 'javascript:alert(1)' })
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
