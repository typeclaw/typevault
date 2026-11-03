import { expect, test } from 'bun:test'

import { collectEntries } from './shared'

test('entry collection drops empty and unusable fields and resolves collisions on the last segment without losing records', () => {
  const result = collectEntries([
    {
      title: 'Crème / GitHub',
      container: 'Work / Team',
      type: 'api_key',
      fields: { key: 'hunter2', password: 'wrong' },
    },
    { title: 'Creme GitHub', container: 'Work Team', type: 'api_key', fields: { key: 'second', 'a=b': 'bad' } },
    { title: 'Creme GitHub', container: 'Work Team', type: 'note', fields: { text: 'third', key: 'wrong', empty: '' } },
    { title: '!!!', type: 'ssh', fields: { private_key: 'fake-private', public_key: '', other: undefined } },
  ])
  expect(result.entries.map((entry) => [String(entry.name), entry.fields])).toEqual([
    ['creme-github/work-team', { key: 'hunter2', password: 'wrong' }],
    ['creme-github/work-team-2', { key: 'second' }],
    ['creme-github/work-team-3', { text: 'third', key: 'wrong' }],
    ['item', { private_key: 'fake-private' }],
  ])
  expect(result.warnings).toHaveLength(3)
  expect(result.warnings.join()).toContain('creme-github/work-team-2: skipped a field with an unusable name')
  expect(result.warnings.join()).toContain('"creme-github/work-team"')
  expect(result.warnings.join()).toContain('"creme-github/work-team-2"')
  expect(result.warnings.join()).toContain('"creme-github/work-team-3"')
  expect(result.warnings.join()).not.toContain('hunter2')
})
