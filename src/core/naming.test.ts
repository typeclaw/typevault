import { describe, expect, it } from 'bun:test'

import { TypeVaultError } from './errors'
import { deriveEnvName, matchesOnly, parseEntryName, parseEntryRef, slugifySegment } from './naming'

describe('parseEntryName', () => {
  it.each([
    ['openai', 'openai'],
    ['GitHub/Bot', 'github/bot'],
    ['google-workspace/team-1', 'google-workspace/team-1'],
    ['tv://github/bot', 'github/bot'],
    ['typevault://GitHub/Bot', 'github/bot'],
  ])('accepts %p as %p', (input, expected) => {
    expect<string>(parseEntryName(input)).toBe(expected)
  })

  it.each(['', 'a/b/c', 'github/', '-github', 'git_hub', 'git hub', 'github//bot', 'café'])('rejects %p', (input) => {
    expect(() => parseEntryName(input)).toThrow(TypeVaultError)
  })
})

describe('parseEntryRef', () => {
  it('splits the field selector off the name', () => {
    expect(parseEntryRef('github/bot#Password')).toEqual({ name: parseEntryName('github/bot'), field: 'password' })
  })

  it.each(['tv://github/bot#password', 'typevault://github/bot#password', 'TV://GitHub/Bot#password'])(
    'accepts the %p scheme form',
    (input) => {
      expect(parseEntryRef(input)).toEqual({ name: parseEntryName('github/bot'), field: 'password' })
    },
  )

  it.each(['op://github/bot#password', 'tv:github/bot', 'tv:///github/bot'])('rejects %p', (input) => {
    expect(() => parseEntryRef(input)).toThrow(TypeVaultError)
  })

  it('leaves the field undefined when no selector is given', () => {
    expect(parseEntryRef('openai').field).toBeUndefined()
  })
})

describe('deriveEnvName', () => {
  it.each([
    ['github/bot', 'password', 'GITHUB_BOT_PASSWORD'],
    ['openai', 'key', 'OPENAI_KEY'],
    ['google-workspace', 'access_token', 'GOOGLE_WORKSPACE_ACCESS_TOKEN'],
  ])('derives %p#%p as %p', (name, field, expected) => {
    expect(deriveEnvName(parseEntryName(name), field)).toBe(expected)
  })
})

describe('slugifySegment', () => {
  it.each([
    ['GitHub (Work)', 'github-work'],
    ['  ', 'item'],
    ['Crème Brûlée', 'creme-brulee'],
  ])('slugifies %p as %p', (input, expected) => {
    expect(slugifySegment(input)).toBe(expected)
  })
})

describe('matchesOnly', () => {
  const name = parseEntryName('github/bot')

  it.each([
    [['github/*'], true],
    [['tv://github/*'], true],
    [['TV://GitHub/Bot'], true],
    [['github/bot'], true],
    [['openai', 'github/personal'], false],
    [['*'], false],
  ])('matches %p as %p', (patterns, expected) => {
    expect(matchesOnly(name, patterns)).toBe(expected)
  })
})
