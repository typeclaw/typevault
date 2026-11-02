import { TypeVaultError } from './errors'

export const ENTRY_TYPES = {
  password: { fields: ['username', 'password', 'totp', 'url'], primary: 'password' },
  api_key: { fields: ['key'], primary: 'key' },
  oauth: {
    fields: ['access_token', 'refresh_token', 'expires_at', 'token_url', 'client_id', 'client_secret'],
    primary: 'access_token',
  },
  ssh: { fields: ['private_key', 'public_key'], primary: 'private_key' },
  totp: { fields: ['seed'], primary: 'seed' },
  note: { fields: ['text'], primary: 'text' },
} as const

export type EntryType = keyof typeof ENTRY_TYPES
export const ENTRY_TYPE_NAMES: readonly string[] = Object.keys(ENTRY_TYPES)

export const isEntryType = (value: string): value is EntryType => Object.hasOwn(ENTRY_TYPES, value)

export function parseEntryType(value: string): EntryType {
  if (isEntryType(value)) return value
  throw new TypeVaultError('invalid', `unknown type "${value}" (expected one of: ${ENTRY_TYPE_NAMES.join(', ')})`)
}

export type EntryName = string & { readonly __brand: 'EntryName' }

const SEGMENT = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const MAX_SEGMENTS = 2

/** Parses `<service>[/<account>]`. Names are case-insensitive and stored lowercase. */
export function parseEntryName(input: string): EntryName {
  const name = input.trim().toLowerCase()
  const segments = name.split('/')
  if (segments.length > MAX_SEGMENTS || !segments.every((segment) => SEGMENT.test(segment))) {
    throw new TypeVaultError(
      'invalid',
      `invalid entry name "${input}" (expected <service>[/<account>], segments [a-z0-9-])`,
    )
  }
  return name as EntryName
}

export type EntryRef = { readonly name: EntryName; readonly field: string | undefined }

/** Parses `<service>[/<account>][#<field>]`. */
export function parseEntryRef(input: string): EntryRef {
  const hash = input.indexOf('#')
  if (hash === -1) return { name: parseEntryName(input), field: undefined }
  const field = input.slice(hash + 1).toLowerCase()
  if (!/^[a-z0-9_]+$/.test(field)) throw new TypeVaultError('invalid', `invalid field "${field}"`)
  return { name: parseEntryName(input.slice(0, hash)), field }
}

export const fieldsOf = (type: EntryType): readonly string[] => ENTRY_TYPES[type].fields
export const primaryField = (type: EntryType): string => ENTRY_TYPES[type].primary

/** `github/bot` + `password` becomes `GITHUB_BOT_PASSWORD`. */
export const deriveEnvName = (name: EntryName, field: string): string =>
  `${name}_${field}`.toUpperCase().replace(/[/-]/g, '_')

/** Turns arbitrary text (an import title, a vault name) into a valid name segment. */
export function slugifySegment(raw: string): string {
  const slug = raw
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return slug === '' ? 'item' : slug
}

/** True when `name` matches any `--only` pattern (exact names or globs such as `github/*`). */
export function matchesOnly(name: EntryName, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => new Bun.Glob(pattern.toLowerCase()).match(name))
}
