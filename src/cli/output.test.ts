import { expect, test } from 'bun:test'

import { table } from './output'

test('table pads wide characters by display width', () => {
  expect(
    table([
      ['국민은행', 'r1'],
      ['github', 'r2'],
    ]),
  ).toBe('국민은행  r1\ngithub    r2')
})
