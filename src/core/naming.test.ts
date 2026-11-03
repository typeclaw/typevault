import { describe, expect, it } from 'bun:test'

import { TypeVaultError } from './errors'
import {
  deriveEnvName,
  findField,
  isSecretField,
  matchesOnly,
  parseEntryName,
  parseEntryRef,
  slugifySegment,
} from './naming'

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
  it('splits the field selector off the name, keeping its case', () => {
    expect(parseEntryRef('github/bot#Password')).toEqual({ name: parseEntryName('github/bot'), field: 'Password' })
  })

  it('takes everything after the first # as the field', () => {
    expect(parseEntryRef('tv://aws/prod#Secret Access Key #2').field).toBe('Secret Access Key #2')
  })

  it.each(['github/bot#', 'github/bot#a=b', 'github/bot# padded'])('rejects the field in %p', (input) => {
    expect(() => parseEntryRef(input)).toThrow(TypeVaultError)
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
    ['aws/prod', 'Secret Access Key', 'AWS_PROD_SECRET_ACCESS_KEY'],
    ['stripe', 'api-key (live)', 'STRIPE_API_KEY_LIVE'],
    ['wifi', 'Clé', 'WIFI_CLE'],
  ])('derives %p#%p as %p', (name, field, expected) => {
    expect(deriveEnvName(parseEntryName(name), field)).toBe(expected)
  })

  it('derives nothing when no letter or digit survives', () => {
    expect(deriveEnvName(parseEntryName('wifi'), '비밀번호')).toBeUndefined()
  })
})

describe('findField', () => {
  const fields = { password: 'a', 'API Key': 'b', token: 'c', TOKEN: 'd' }

  it.each([
    ['password', 'password'],
    ['Password', 'password'],
    ['api key', 'API Key'],
    ['TOKEN', 'TOKEN'],
    ['Token', undefined],
    ['missing', undefined],
  ])('finds %p as %p', (field, expected) => {
    expect(findField(fields, field)).toBe(expected)
  })
})

describe('isSecretField', () => {
  it.each([
    ['username', false],
    ['url', false],
    ['password', true],
    ['text', true],
    ['Webhook Secret', true],
    ['Username', true],
  ])('treats %p as secret: %p', (field, expected) => {
    expect(isSecretField(field)).toBe(expected)
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
