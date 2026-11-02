import { expect, test } from 'bun:test'

import { parseTypeclaw } from './typeclaw'

test('typeclaw imports only prefixed secrets with original env names and collision warnings', () => {
  const result = parseTypeclaw(
    'IGNORED=hunter2\nTYPECLAW_SECRET_=ignored\nexport TYPECLAW_SECRET_GITHUB=hunter2\n' +
      'TYPECLAW_SECRET_GITHUB="second\\nline"\nTYPECLAW_SECRET_EMPTY=\n',
  )
  expect(result.entries.map((entry) => [entry.name, entry.type, entry.fields, entry.env, entry.tags])).toEqual([
    ['github', 'password', { password: 'hunter2' }, 'TYPECLAW_SECRET_GITHUB', []],
    ['github-2', 'password', { password: 'second\nline' }, 'TYPECLAW_SECRET_GITHUB', []],
    ['empty', 'password', {}, 'TYPECLAW_SECRET_EMPTY', []],
  ])
  expect(result.warnings).toHaveLength(1)
  expect(result.warnings[0]).toContain('"github"')
  expect(result.warnings[0]).toContain('"github-2"')
  expect(result.warnings.join()).not.toContain('hunter2')
})
