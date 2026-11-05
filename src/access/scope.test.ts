import { expect, it } from 'bun:test'

import { parseTtl } from './scope'

it.each(['0s', '99999999999d', `${'9'.repeat(400)}d`])('rejects unusable TTL %s as invalid', (text) => {
  expect(() => parseTtl(text)).toThrow(expect.objectContaining({ code: 'invalid' }))
})

it.each([
  ['1s', 1_000],
  ['30m', 1_800_000],
  ['1h', 3_600_000],
  ['3650d', 315_360_000_000],
] as const)('accepts bounded TTL %s', (text, ms) => {
  expect(parseTtl(text)).toBe(ms)
})
