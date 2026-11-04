import { describe, expect, it } from 'bun:test'

import { TypeVaultError } from './errors'
import {
  deriveEnvName,
  findField,
  defaultField,
  isFieldName,
  resolveField,
  type Field,
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

  it.each(['github/bot#', 'github/bot#a=b', 'github/bot# padded', 'github/bot#$default', 'github/bot#$other'])(
    'rejects the field in %p',
    (input) => {
      expect(() => parseEntryRef(input)).toThrow(TypeVaultError)
    },
  )

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
    ['openai', '$default', 'OPENAI'],
    ['github/bot', '$default', 'GITHUB_BOT'],
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

describe('defaultField', () => {
  it.each([
    [{ $default: 'a', password: 'b' }, '$default'],
    [{ password: 'a' }, 'password'],
  ])('resolves %p to %p', (fields, expected) => {
    expect(defaultField(fields)).toBe(expected)
  })
  it('lists the fields when a bare reference is ambiguous', () => {
    expect(() => defaultField({ username: 'a', password: 'b' }, 'github')).toThrow(
      'github has several fields, name one: username, password',
    )
  })
  it('rejects entries with no fields', () => {
    expect(() => defaultField({})).toThrow(TypeVaultError)
  })
})
describe('reserved field names', () => {
  it.each([
    ['$default', true],
    ['$other', false],
    ['$default.part', false],
    ['custom', true],
  ])('accepts %p: %p', (field, expected) => {
    expect(isFieldName(field)).toBe(expected)
  })
})
describe('compound fields', () => {
  const fields: Readonly<Record<string, Field>> = {
    session: { type: 'oauth', value: { access_token: 'token', refresh_token: 'refresh' } },
    'session.access_token': { type: 'text', value: 'literal' },
    plain: { type: 'secret', value: 'secret' },
  }
  it.each([
    ['session.refresh_token', { type: 'secret' as const, value: 'refresh' }],
    ['session.access_token', { type: 'text' as const, value: 'literal' }],
    ['session.missing', undefined],
    ['plain.part', undefined],
  ])('resolves %p', (wanted, expected) => {
    expect(resolveField(fields, wanted)).toEqual(expected)
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
