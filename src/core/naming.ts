import { TypeVaultError } from './errors'

export type FieldType = 'secret' | 'text' | 'totp' | 'oauth'
export type Field =
  | { readonly type: 'secret' | 'text' | 'totp'; readonly value: string }
  | { readonly type: 'oauth'; readonly value: Readonly<Record<string, string>> }
export const PRESETS = {
  password: { fields: { username: 'text', password: 'secret', totp: 'totp', url: 'text' }, input: 'password' },
  api_key: { fields: { $default: 'secret' }, input: '$default' },
  oauth: { fields: { $default: 'oauth' }, input: '$default' },
  ssh: { fields: { private_key: 'secret', public_key: 'text' }, input: 'private_key' },
  totp: { fields: { $default: 'totp' }, input: '$default' },
  note: { fields: { $default: 'secret' }, input: '$default' },
} as const satisfies Record<string, { readonly fields: Readonly<Record<string, FieldType>>; readonly input: string }>
export type Preset = keyof typeof PRESETS
export const isPreset = (value: string): value is Preset => Object.hasOwn(PRESETS, value)
export function parsePreset(value: string): Preset {
  if (isPreset(value)) return value
  throw new TypeVaultError('invalid', `unknown preset "${value}" (expected one of: ${Object.keys(PRESETS).join(', ')})`)
}

export type EntryName = string & { readonly __brand: 'EntryName' }

const SEGMENT = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const MAX_SEGMENTS = 2

/**
 * The one way to point at an entry: `typevault://<service>[/<account>][#<field>]`. The scheme may be left out
 * (`github/bot#password`) as shorthand. Every name, `--only` pattern and env reference goes through the parsers
 * below.
 */
export const ENTRY_NAME_SYNTAX = 'typevault://<service>[/<account>]'
export const ENTRY_REF_SYNTAX = `${ENTRY_NAME_SYNTAX}[#<field>]`

const REF_SCHEME = /^typevault:\/\//i

/** True when `input` carries the `typevault://` scheme, as an env value `run` resolves. */
export const hasRefScheme = (input: string): boolean => REF_SCHEME.test(input.trim())

/** An `--only` pattern (a name or a glob) in the form names are stored in: no scheme, lowercase. */
export const entryPattern = (input: string): string => input.trim().replace(REF_SCHEME, '').toLowerCase()

/** Parses `[typevault://]<service>[/<account>]`. Names are case-insensitive, stored lowercase and without the scheme. */
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
 * An entry may hold any field: up to 64 characters, no surrounding
 * whitespace, no control characters and no `=` (which `--field name=value` splits on). Case is kept.
 */
export const isFieldName = (field: string): boolean =>
  (!field.startsWith('$') || field === '$default') &&
  field !== '' &&
  field.length <= MAX_FIELD_LENGTH &&
  field.trim() === field &&
  !/[\p{Cc}=]/u.test(field)

/** Parses `[typevault://]<service>[/<account>][#<field>]`. The field is everything after the first `#`. */
export function parseEntryRef(input: string): EntryRef {
  const hash = input.indexOf('#')
  if (hash === -1) return { name: parseEntryName(input), field: undefined }
  const field = input.slice(hash + 1)
  if (field === '$default' || !isFieldName(field)) throw new TypeVaultError('invalid', `invalid field "${field}"`)
  return { name: parseEntryName(input.slice(0, hash)), field }
}

/** The stored key `field` refers to: an exact match, else the only one equal ignoring case. */
export function findField(fields: Readonly<Record<string, unknown>>, field: string): string | undefined {
  if (Object.hasOwn(fields, field)) return field
  const matches = Object.keys(fields).filter((key) => key.toLowerCase() === field.toLowerCase())
  return matches.length === 1 ? matches[0] : undefined
}

/** The field a reference without `#field` reads: `$default`, else the only field, else none. */
export function defaultFieldOf(fields: Readonly<Record<string, unknown>>): string | undefined {
  if (Object.hasOwn(fields, '$default')) return '$default'
  const names = Object.keys(fields)
  return names.length === 1 ? names[0] : undefined
}

export function defaultField(fields: Readonly<Record<string, unknown>>, name = 'entry'): string {
  const field = defaultFieldOf(fields)
  if (field !== undefined) return field
  const names = Object.keys(fields)
  throw new TypeVaultError(
    'not_found',
    names.length === 0 ? `${name} has no fields` : `${name} has several fields, name one: ${names.join(', ')}`,
  )
}

/**
 * The field `wanted` names, else a part of a compound field: `oauth.refresh_token`, or `refresh_token` alone for a
 * part of the default field (which a ref can't name, since `#$default` is refused).
 */
export function resolveField(fields: Readonly<Record<string, Field>>, wanted: string): Field | undefined {
  const key = findField(fields, wanted)
  if (key !== undefined) return fields[key]
  const dot = wanted.lastIndexOf('.')
  const parent = dot === -1 ? defaultFieldOf(fields) : findField(fields, wanted.slice(0, dot))
  const field = parent === undefined ? undefined : fields[parent]
  if (field === undefined) return undefined
  switch (field.type) {
    case 'oauth': {
      const part = field.value[wanted.slice(dot + 1)]
      return part === undefined ? undefined : { type: 'secret', value: part }
    }
    case 'secret':
    case 'text':
    case 'totp':
      return undefined
    default:
      return assertNever(field)
  }
}
export function fieldValue(field: Field): string {
  switch (field.type) {
    case 'oauth':
      return field.value['access_token'] ?? ''
    case 'secret':
    case 'text':
    case 'totp':
      return field.value
    default:
      return assertNever(field)
  }
}
export function fieldStrings(field: Field): readonly string[] {
  switch (field.type) {
    case 'oauth':
      return Object.values(field.value)
    case 'secret':
    case 'text':
    case 'totp':
      return [field.value]
    default:
      return assertNever(field)
  }
}
function assertNever(value: never): never {
  throw new TypeVaultError('invalid', `unexpected field ${JSON.stringify(value)}`)
}

/**
 * `github/bot` + `password` becomes `GITHUB_BOT_PASSWORD`, and `Secret Access Key` becomes `..._SECRET_ACCESS_KEY`.
 * Undefined when no letter or digit of the field survives (a non-Latin name): such a field is reachable only
 * through a `typevault://` ref.
 */
export function deriveEnvName(name: EntryName, field: string): string | undefined {
  if (field === '$default') return name.toUpperCase().replace(/[/-]/g, '_')
  const suffix = field
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return suffix === '' ? undefined : `${name.toUpperCase().replace(/[/-]/g, '_')}_${suffix}`
}

/** Turns arbitrary text (an import title, a vault name) into a valid name segment. */
export function slugifySegment(raw: string, fallback = 'item'): string {
  const slug = raw
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return slug === '' ? fallback : slug
}

/** True when `name` matches any `--only` pattern (exact names or globs such as `github/*`). */
export function matchesOnly(name: EntryName, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => new Bun.Glob(entryPattern(pattern)).match(name))
}

/**
 * Variables that change how the child or its interpreter loads code. A lower tier can write entries a higher
 * tier's `run` loads, so an entry must never set these, whether by --env override or by a derived name.
 */
const RESERVED_ENV = new RegExp(
  `^(${[
    // the shell and process
    'PATH|HOME|SHELL|USER|LOGNAME|TMPDIR|IFS|ENV|BASH_ENV|PS4|PROMPT_COMMAND|ZDOTDIR|XDG_\\w*',
    // programs a tool may launch
    'EDITOR|VISUAL|PAGER|BROWSER|MANPAGER|LESS\\w*|SSH_ASKPASS\\w*|SSH_AUTH_SOCK|GIT_\\w*',
    // interpreters and loaders
    'NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|RUBYOPT|RUBYLIB|PERL5OPT|PERL5LIB|PERLLIB',
    'NODE_TLS_REJECT_UNAUTHORIZED|CLASSPATH|GEM_PATH|GEM_HOME|GCONV_PATH',
    'JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|LD_\\w*|DYLD_\\w*|BUN_\\w*|NPM_CONFIG_\\w*',
    // where traffic goes and which certificates it trusts
    '\\w*_PROXY|SOCKS_\\w*|\\w*_CA_BUNDLE|\\w*_CA_CERTS|\\w*CERT_FILE|SSL_CERT_DIR|SSLKEYLOGFILE',
    // tool config directories, without reserving unrelated names such as CUSTOMER_HOME
    'CURL_HOME|WGETRC',
    // package managers and toolchains that fetch or run code
    'PIP_\\w*|UV_\\w*|CARGO_\\w*|RUSTC_WRAPPER|RUSTC|GOFLAGS|GOPROXY|GONOSUMDB|GOPRIVATE|DOCKER_HOST|DOCKER_CONFIG',
    'TYPEVAULT_\\w*',
  ].join('|')})$`,
)

export const isReservedEnvName = (name: string): boolean => RESERVED_ENV.test(name)

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/

/** A name `run` may set: well-formed and not reserved. */
export const isUsableEnvName = (name: string): boolean => ENV_NAME.test(name) && !isReservedEnvName(name)
