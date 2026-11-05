import { expect, test } from 'bun:test'

import { collectEntries, withCustomFields } from './shared'

test('entry collection drops empty and unusable fields and resolves collisions on the last segment without losing records', () => {
  const result = collectEntries([
    {
      title: 'Crème / GitHub',
      preset: 'api_key',
      fields: { key: 'hunter2', password: 'wrong' },
    },
    { title: 'Crème GitHub', preset: 'api_key', fields: { key: 'second', 'a=b': 'bad' } },
    {
      title: 'CRÈME GitHub',
      preset: 'note',
      fields: { $default: 'third', key: 'wrong', empty: '' },
    },
    { title: '!!!', preset: 'ssh', fields: { private_key: 'fake-private', public_key: '', other: undefined } },
  ])
  expect(result.entries.map((entry) => [String(entry.name), entry.fields])).toEqual([
    ['crème-github', { key: { type: 'secret', value: 'hunter2' }, password: { type: 'secret', value: 'wrong' } }],
    ['crème-github-2', { key: { type: 'secret', value: 'second' } }],
    ['crème-github-3', { $default: { type: 'secret', value: 'third' }, key: { type: 'secret', value: 'wrong' } }],
  ])
  expect(result.warnings).toHaveLength(4)
  expect(result.warnings.join()).toContain('crème-github-2: skipped a field with an unusable name')
  expect(result.warnings.join()).toContain('"crème-github"')
  expect(result.warnings.join()).toContain('"crème-github-2"')
  expect(result.warnings.join()).toContain('"crème-github-3"')
  expect(result.warnings.join()).toContain('skipped "!!!"')
  expect(result.warnings.join()).not.toContain('hunter2')
})

test('entry collection keeps non-Latin titles, @ + and ., and skips names that mix Latin with lookalike scripts', () => {
  const result = collectEntries([
    { title: '코레일+', preset: 'password', url: 'https://www.letskorail.com', fields: {} },
    { title: '국민은행 (법인)', preset: 'password', fields: {} },
    { title: 'Githuь', preset: 'password', fields: {} },
    { title: ' Dev@Example.com. ', preset: 'password', fields: {} },
    { title: 'AWSユーザー', preset: 'password', fields: {} },
  ])
  expect(result.entries.map((entry) => String(entry.name))).toEqual([
    '코레일+',
    '국민은행-법인',
    'dev@example.com',
    'awsユーザー',
  ])
  expect(result.warnings).toEqual(['skipped "Githuь": its title makes no usable entry name'])
})

test('entry collection treats two spellings of one name as a collision, keeping both values', () => {
  const result = collectEntries([
    { title: 'J\u030C', preset: 'api_key', fields: { $default: 'first' } },
    { title: '\u01F0', preset: 'api_key', fields: { $default: 'second' } },
  ])
  expect(result.entries.map((entry) => [String(entry.name), entry.fields])).toEqual([
    ['\u01F0', { $default: { type: 'secret', value: 'first' } }],
    ['\u01F0-2', { $default: { type: 'secret', value: 'second' } }],
  ])
})

test('entry collection gives a login whose name mixes scripts a stable stand-in, keeping its items', () => {
  const result = collectEntries([
    { title: 'GitHub', preset: 'password', fields: { username: 'Работа Private', password: 'a' } },
    { title: 'Memo', preset: 'password', fields: { username: 'Работа Private', password: 'b' } },
  ])
  const standIn = String(result.entries[0]?.name).split('/')[1] ?? ''
  expect(standIn).toMatch(/^[0-9a-f]{8}$/)
  expect(result.entries.map((entry): string => entry.name)).toEqual([`github/${standIn}`, `memo/${standIn}`])
  expect(result.warnings).toEqual([`"Работа Private" makes no usable name segment; its entries use "${standIn}"`])
})

test('entry collection names the account after the login, never a vault, and suffixes a repeated login', () => {
  const result = collectEntries([
    { title: 'GitHub', preset: 'password', fields: { username: 'Dev@Example.com', password: 'a' } },
    { title: 'GitHub', preset: 'password', fields: { username: { type: 'text', value: 'dev@example.com' } } },
    { title: 'GitHub', preset: 'password', fields: { username: '—', password: 'b' } },
    { title: 'GitHub', preset: 'api_key', fields: { $default: 'c' } },
  ])
  expect(result.entries.map((entry) => String(entry.name))).toEqual([
    'github/dev@example.com',
    'github/dev@example.com-2',
    'github',
    'github-2',
  ])
})

test('custom fields keep their labels but never repeat or replace a template field', () => {
  expect(
    withCustomFields({ key: 'k', username: undefined }, [
      ['credential', 'k'],
      [' Webhook Secret ', 'w'],
      ['username', 'u'],
      ['', 'nameless'],
      ['Region', ''],
      ['Webhook Secret', 'second'],
    ]),
  ).toEqual({ 'Webhook Secret': 'w', key: 'k', username: undefined })
})
