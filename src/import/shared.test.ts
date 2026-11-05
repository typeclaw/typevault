import { expect, test } from 'bun:test'

import { collectEntries, withCustomFields } from './shared'

test('entry collection drops empty and unusable fields and resolves collisions on the last segment without losing records', () => {
  const result = collectEntries([
    {
      title: 'Crème / GitHub',
      container: 'Work / Team',
      preset: 'api_key',
      fields: { key: 'hunter2', password: 'wrong' },
    },
    { title: 'Creme GitHub', container: 'Work Team', preset: 'api_key', fields: { key: 'second', 'a=b': 'bad' } },
    {
      title: 'Creme GitHub',
      container: 'Work Team',
      preset: 'note',
      fields: { $default: 'third', key: 'wrong', empty: '' },
    },
    { title: '!!!', preset: 'ssh', fields: { private_key: 'fake-private', public_key: '', other: undefined } },
  ])
  expect(result.entries.map((entry) => [String(entry.name), entry.fields])).toEqual([
    [
      'creme-github/work-team',
      { key: { type: 'secret', value: 'hunter2' }, password: { type: 'secret', value: 'wrong' } },
    ],
    ['creme-github/work-team-2', { key: { type: 'secret', value: 'second' } }],
    [
      'creme-github/work-team-3',
      { $default: { type: 'secret', value: 'third' }, key: { type: 'secret', value: 'wrong' } },
    ],
    ['item', { private_key: { type: 'secret', value: 'fake-private' } }],
  ])
  expect(result.warnings).toHaveLength(3)
  expect(result.warnings.join()).toContain('creme-github/work-team-2: skipped a field with an unusable name')
  expect(result.warnings.join()).toContain('"creme-github/work-team"')
  expect(result.warnings.join()).toContain('"creme-github/work-team-2"')
  expect(result.warnings.join()).toContain('"creme-github/work-team-3"')
  expect(result.warnings.join()).not.toContain('hunter2')
})

test('entry collection names a title with no Latin letters after its URL, and falls back to item without one', () => {
  const result = collectEntries([
    {
      title: '코레일+',
      container: 'Private',
      preset: 'password',
      url: 'app://TEAMID.com.korail.KorailTalk',
      fields: {},
    },
    { title: '코레일', preset: 'password', url: 'https://www.letskorail.com/login', fields: {} },
    { title: '네이버', preset: 'password', url: 'https://nid.naver.co.kr', fields: {} },
    { title: '코레일', preset: 'password', fields: {} },
  ])
  expect(result.entries.map((entry) => String(entry.name))).toEqual([
    'korailtalk/private',
    'letskorail',
    'naver',
    'item',
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
