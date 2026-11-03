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

/**
 * The one way to point at an entry: `tv://<service>[/<account>][#<field>]`. `typevault://` is an alias, and the
 * scheme may be left out (`github/bot#password`) as shorthand. Every name, `--only` pattern and env reference goes
 * through the parsers below.
 */
export const ENTRY_NAME_SYNTAX = 'tv://<service>[/<account>]'
export const ENTRY_REF_SYNTAX = `${ENTRY_NAME_SYNTAX}[#<field>]`

const REF_SCHEME = /^(?:tv|typevault):\/\//i

/** True when `input` carries the `tv://` (or `typevault://`) scheme, as an env value `run` resolves. */
export const hasRefScheme = (input: string): boolean => REF_SCHEME.test(input.trim())

/** An `--only` pattern (a name or a glob) in the form names are stored in: no scheme, lowercase. */
export const entryPattern = (input: string): string => input.trim().replace(REF_SCHEME, '').toLowerCase()

/** Parses `[tv://]<service>[/<account>]`. Names are case-insensitive and stored lowercase, without the scheme. */
export function parseEntryName(input: string): EntryName {
  const name = entryPattern(input)
  const segments = name.split('/')
  if (segments.length > MAX_SEGMENTS || !segments.every((segment) => SEGMENT.test(segment))) {
    throw new TypeVaultError(
      'invalid',
      `invalid entry name "${input}" (expected ${ENTRY_NAME_SYNTAX}, segments [a-z0-9-])`,
    )
  }
  return name as EntryName
}

export type EntryRef = { readonly name: EntryName; readonly field: string | undefined }

const MAX_FIELD_LENGTH = 64

/**
 * A type lists the fields it suggests, but an entry may hold any field: up to 64 characters, no surrounding
 * whitespace, no control characters and no `=` (which `--field name=value` splits on). Case is kept.
 */
export const isFieldName = (field: string): boolean =>
  field !== '' && field.length <= MAX_FIELD_LENGTH && field.trim() === field && !/[\p{Cc}=]/u.test(field)

/** Parses `[tv://]<service>[/<account>][#<field>]`. The field is everything after the first `#`. */
export function parseEntryRef(input: string): EntryRef {
  const hash = input.indexOf('#')
  if (hash === -1) return { name: parseEntryName(input), field: undefined }
  const field = input.slice(hash + 1)
  if (!isFieldName(field)) throw new TypeVaultError('invalid', `invalid field "${field}"`)
  return { name: parseEntryName(input.slice(0, hash)), field }
}

/** The stored key `field` refers to: an exact match, else the only one equal ignoring case. */
export function findField(fields: Readonly<Record<string, unknown>>, field: string): string | undefined {
  if (Object.hasOwn(fields, field)) return field
  const matches = Object.keys(fields).filter((key) => key.toLowerCase() === field.toLowerCase())
  return matches.length === 1 ? matches[0] : undefined
}

/**
 * Fields known to hold no secret. Every other field, custom ones included, is never accepted on the command line,
 * where `ps` and shell history see it.
 */
const PLAIN_FIELDS: ReadonlySet<string> = new Set([
  'username',
  'url',
  'token_url',
  'client_id',
  'expires_at',
  'public_key',
])
export const isSecretField = (field: string): boolean => !PLAIN_FIELDS.has(field)

export const fieldsOf = (type: EntryType): readonly string[] => ENTRY_TYPES[type].fields
export const primaryField = (type: EntryType): string => ENTRY_TYPES[type].primary

/**
 * `github/bot` + `password` becomes `GITHUB_BOT_PASSWORD`, and `Secret Access Key` becomes `..._SECRET_ACCESS_KEY`.
 * Undefined when no letter or digit of the field survives (a non-Latin name): such a field is reachable only
 * through a `tv://` ref.
 */
export function deriveEnvName(name: EntryName, field: string): string | undefined {
  const suffix = field
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return suffix === '' ? undefined : `${name.toUpperCase().replace(/[/-]/g, '_')}_${suffix}`
}

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
  return patterns.some((pattern) => new Bun.Glob(entryPattern(pattern)).match(name))
}

/**
 * Variables that change how the child or its interpreter loads code. A lower group can write entries a higher
 * group's `run` loads, so an entry must never set these, whether by --env override or by a derived name.
 */
const RESERVED_ENV = new RegExp(
  `^(${[
    // the shell and process
    'PATH|HOME|SHELL|USER|LOGNAME|TMPDIR|IFS|ENV|BASH_ENV|PS4|PROMPT_COMMAND|ZDOTDIR|XDG_\\w*',
    // programs a tool may launch
    'EDITOR|VISUAL|PAGER|BROWSER|MANPAGER|LESS\\w*|SSH_ASKPASS\\w*|SSH_AUTH_SOCK|GIT_\\w*',
    // interpreters and loaders
    'NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|RUBYOPT|RUBYLIB|PERL5OPT|PERL5LIB|PERLLIB',
    'JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|LD_\\w*|DYLD_\\w*|BUN_\\w*|NPM_CONFIG_\\w*',
    // where traffic goes and which certificates it trusts
    'HTTPS?_PROXY|ALL_PROXY|NO_PROXY|SSL_CERT_FILE|SSL_CERT_DIR|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE',
    // package managers and toolchains that fetch or run code
    'PIP_\\w*|UV_\\w*|CARGO_\\w*|RUSTC_WRAPPER|RUSTC|GOFLAGS|GOPROXY|GONOSUMDB|GOPRIVATE|DOCKER_HOST|DOCKER_CONFIG',
    'TYPEVAULT_\\w*',
  ].join('|')})$`,
)

export const isReservedEnvName = (name: string): boolean => RESERVED_ENV.test(name)

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/

/** A name `run` may set: well-formed and not reserved. */
export const isUsableEnvName = (name: string): boolean => ENV_NAME.test(name) && !isReservedEnvName(name)
