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

/**
 * Variables that change how the child or its interpreter loads code. A lower group can write entries a higher
 * group's `run` loads, so an entry must never set these, whether by --env override or by a derived name.
 */
const RESERVED_ENV =
  /^(PATH|HOME|SHELL|USER|LOGNAME|TMPDIR|IFS|ENV|BASH_ENV|PS4|PROMPT_COMMAND|EDITOR|VISUAL|PAGER|BROWSER|NODE_OPTIONS|NODE_PATH|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|RUBYOPT|RUBYLIB|PERL5OPT|PERL5LIB|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|SSH_AUTH_SOCK|GIT_SSH|GIT_SSH_COMMAND|GIT_EXEC_PATH|GIT_CONFIG_\w*|LD_\w*|DYLD_\w*|BUN_\w*|NPM_CONFIG_\w*|TYPEVAULT_\w*)$/

export const isReservedEnvName = (name: string): boolean => RESERVED_ENV.test(name)

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/

/** A name `run` may set: well-formed and not reserved. */
export const isUsableEnvName = (name: string): boolean => ENV_NAME.test(name) && !isReservedEnvName(name)
