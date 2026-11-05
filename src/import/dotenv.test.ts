import { expect, test } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { parseDotenv } from './dotenv'

test('dotenv retains variable names and parses quoted multiline secrets without expansion', () => {
  const result = parseDotenv(
    "# comment\r\nexport OPENAI_API_KEY=hunter2 # hidden\r\nLITERAL='$HOME\\n#literal'\n" +
      'MULTI="first\\nsecond\nthird \\"quoted\\""\nEMPTY=\nOPENAI_API_KEY=other\n',
  )
  expect(result.entries.map((entry) => [entry.name, entry.fields, entry.env])).toEqual([
    ['openai-api-key', { $default: { type: 'secret', value: 'other' } }, 'OPENAI_API_KEY'],
    ['literal', { $default: { type: 'secret', value: '$HOME\\n#literal' } }, 'LITERAL'],
    ['multi', { $default: { type: 'secret', value: 'first\nsecond\nthird "quoted"' } }, 'MULTI'],
    ['empty', {}, 'EMPTY'],
  ])
  expect(result.warnings).toEqual([])
  expect(result.warnings.join()).not.toContain('hunter2')
})

test.each(['broken', 'KEY="unclosed', "KEY='unclosed", 'KEY="value"junk', '2KEY=value'])(
  'dotenv rejects malformed assignments without exposing values: %p',
  (text) => {
    expect(() => parseDotenv(text)).toThrow(TypeVaultError)
  },
)
