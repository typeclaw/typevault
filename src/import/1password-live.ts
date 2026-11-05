import type { Client } from '@1password/sdk'
import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { findField, type Field } from '../core/naming'
import { collectEntries, loginOf, parseExternal, parseJson, withCustomFields, type ImportItem } from './shared'
import type { ImportResult } from './types'

export const ONEPASSWORD_VIAS = ['sdk', 'op'] as const
export type OnePasswordVia = (typeof ONEPASSWORD_VIAS)[number]

/** Several values of one filter match any of them; different filters must all match. */
export type OnePasswordOptions = {
  readonly via: OnePasswordVia
  readonly accounts?: readonly string[]
  readonly vaults?: readonly string[]
  readonly tags?: readonly string[]
}

/** Runs `op` with `args`; `input` is piped to stdin, so secrets never land in argv. */
export type RunOp = (args: readonly string[], input?: string) => Promise<string>

export type SdkClient = {
  readonly vaults: { list(): Promise<readonly { readonly id: string; readonly title: string }[]> }
  readonly items: {
    list(
      vaultId: string,
      ...filters: { type: 'ByState'; content: { active: boolean; archived: boolean } }[]
    ): Promise<readonly { readonly id: string; readonly tags: readonly string[] }[]>
    getAll(
      vaultId: string,
      itemIds: string[],
    ): Promise<{ readonly individualResponses: readonly { readonly content?: unknown; readonly error?: unknown }[] }>
  }
}

export type ConnectSdk = (account: string) => Promise<SdkClient>

const UNSUPPORTED = 'skipped unsupported 1Password item category'
// Each `op item get` is its own process and each SDK vault read a round trip, so a few run at once; more would
// mostly queue behind the desktop app and risk 1Password's rate limits.
const CONCURRENCY = 8
// Field types kept as custom fields; dates, menus, addresses and keys don't read as one string.
const OP_TEXT_TYPES: ReadonlySet<string> = new Set(['STRING', 'CONCEALED', 'URL', 'EMAIL', 'PHONE', 'OTP'])
const SDK_TEXT_TYPES: ReadonlySet<string> = new Set(['Text', 'Concealed', 'Url', 'Email', 'Phone', 'Totp'])

export async function read1Password(
  options: OnePasswordOptions,
  deps: { readonly runOp?: RunOp; readonly connectSdk?: ConnectSdk } = {},
): Promise<ImportResult> {
  const accounts = options.accounts ?? []
  const filters: Filters = { vaults: options.vaults ?? [], tags: options.tags ?? [] }
  // `op --tags` takes a comma-separated list, so one tag can't hold a comma.
  if (filters.tags.some((tag) => tag === '' || tag.includes(','))) {
    throw new TypeVaultError('invalid', '--tag values must be non-empty and contain no comma')
  }
  const collected: Collected = { items: [], warnings: [], matchedVaults: new Set() }
  if (options.via === 'op') {
    const runOp = deps.runOp ?? spawnOp
    for (const account of accounts.length === 0 ? [undefined] : accounts) {
      await readOp(account, filters, runOp, collected)
    }
  } else {
    if (accounts.length === 0) {
      throw new TypeVaultError('invalid', '--account is required with --via sdk (the account name shown in 1Password)')
    }
    const connect = deps.connectSdk ?? connectDesktopSdk
    for (const account of accounts) await readSdk(account, filters, connect, collected)
  }
  // A vault may live in only one of several accounts, so a requested vault is missing only if no account had it.
  const missing = filters.vaults.find((vault) => !collected.matchedVaults.has(vault))
  if (missing !== undefined) throw new TypeVaultError('not_found', `1Password vault "${missing}" was not found`)
  return collectEntries(collected.items, collected.warnings)
}

type Filters = { readonly vaults: readonly string[]; readonly tags: readonly string[] }
type Collected = { readonly items: ImportItem[]; readonly warnings: string[]; readonly matchedVaults: Set<string> }

const OpVaultListSchema = z.array(z.object({ id: z.string(), name: z.string().default('') }))
const OpListSchema = z.array(
  z.object({ id: z.string(), vault: z.object({ id: z.string() }), tags: z.array(z.string()).default([]) }),
)
const OpItemSchema = z.object({
  title: z.string(),
  category: z.string(),
  vault: z.object({ name: z.string() }),
  tags: z.array(z.string()).default([]),
  urls: z.array(z.object({ href: z.string(), primary: z.boolean().optional() })).default([]),
  fields: z
    .array(
      z.object({
        id: z.string().default(''),
        type: z.string().default(''),
        purpose: z.string().optional(),
        label: z.string().default(''),
        value: z.string().optional(),
        ssh_formats: z.object({ openssh: z.object({ value: z.string() }).optional() }).optional(),
      }),
    )
    .default([]),
})

async function readOp(
  accountName: string | undefined,
  filters: Filters,
  runOp: RunOp,
  collected: Collected,
): Promise<void> {
  const account = accountName === undefined ? [] : ['--account', accountName]
  const tags = filters.tags.length === 0 ? [] : ['--tags', filters.tags.join(',')]
  let scopes: readonly (readonly string[])[] = [[]]
  if (filters.vaults.length > 0) {
    const vaults = parseJson(await runOp(['vault', 'list', '--format', 'json', ...account]), OpVaultListSchema, 'op')
    scopes = vaults
      .filter((vault) => matchVault(vault.id, vault.name, filters.vaults, collected.matchedVaults))
      .map((vault) => ['--vault', vault.id])
  }
  const listed: z.infer<typeof OpListSchema> = []
  for (const scope of scopes) {
    const items = parseJson(
      await runOp(['item', 'list', '--format', 'json', ...scope, ...tags, ...account]),
      OpListSchema,
      'op',
    )
    // `op --tags` also matches nested tags (`tag/child`): those name the fields to import.
    listed.push(...items.filter((item) => tagSelection(item.tags, filters.tags) !== undefined))
  }
  const fetched = await mapLimit(listed, CONCURRENCY, async (entry) => {
    const args = ['item', 'get', entry.id, '--vault', entry.vault.id, '--reveal', '--format', 'json', ...account]
    return { ...parseJson(await runOp(args), OpItemSchema, 'op'), id: entry.id, vaultId: entry.vault.id }
  })
  for (const item of fetched) {
    const mapped = mapOpItem(item)
    if (mapped === undefined) collected.warnings.push(UNSUPPORTED)
    else {
      const selected = selectFields(mapped, item.title, item.tags, filters.tags, collected.warnings)
      if (selected !== undefined)
        collected.items.push({ ...selected, title: item.title, source: onePasswordSource(item.vaultId, item.id) })
    }
  }
}

/** Maps `values` with at most `limit` calls in flight, keeping input order; stops starting new calls on a failure. */
async function mapLimit<T, R>(values: readonly T[], limit: number, map: (value: T) => Promise<R>): Promise<R[]> {
  const results: R[] = []
  let next = 0
  const worker = async () => {
    while (next < values.length) {
      const index = next++
      try {
        results[index] = await map(values[index] as T)
      } catch (error) {
        next = values.length
        throw error
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, worker))
  return results
}

function mapOpItem(item: z.infer<typeof OpItemSchema>): Omit<ImportItem, 'title'> | undefined {
  const mapped = mapOpTemplate(item)
  if (mapped === undefined) return undefined
  // Built-in fields (username, password, notes) carry a purpose; custom ones don't.
  const labeled = item.fields
    .filter((field) => field.purpose === undefined && OP_TEXT_TYPES.has(field.type))
    .map(
      (field) =>
        [
          field.label,
          field.value === undefined
            ? undefined
            : {
                type:
                  field.type === 'CONCEALED'
                    ? ('secret' as const)
                    : field.type === 'OTP'
                      ? ('totp' as const)
                      : ('text' as const),
                value: field.value,
              },
        ] as const,
    )
  return { ...mapped, fields: withCustomFields(mapped.fields, labeled) }
}

function mapOpTemplate(item: z.infer<typeof OpItemSchema>): Omit<ImportItem, 'title'> | undefined {
  const value = (match: (field: (typeof item.fields)[number]) => boolean) => item.fields.find(match)?.value
  const named = (names: readonly string[]) =>
    value((field) => names.includes(field.id.toLowerCase()) || names.includes(field.label.toLowerCase()))
  const url = (item.urls.find((link) => link.primary) ?? item.urls[0])?.href
  switch (item.category) {
    case 'LOGIN':
    case 'PASSWORD':
      return {
        preset: 'password',
        fields: {
          username: value((field) => field.purpose === 'USERNAME'),
          password: value((field) => field.purpose === 'PASSWORD'),
          totp: value((field) => field.type === 'OTP'),
          url,
        },
        ...(url === undefined ? {} : { url }),
      }
    case 'SECURE_NOTE':
      return { preset: 'note', fields: { $default: value((field) => field.purpose === 'NOTES') } }
    case 'API_CREDENTIAL':
      return { preset: 'api_key', fields: { $default: named(['credential', 'api key', 'api_key', 'key']) } }
    case 'SSH_KEY': {
      const key = item.fields.find((field) => field.type === 'SSHKEY')
      return {
        preset: 'ssh',
        fields: {
          private_key: key?.ssh_formats?.openssh?.value ?? key?.value,
          public_key: named(['public_key', 'public key']),
        },
      }
    }
    default:
      return undefined
  }
}

/** An item's source id. 1Password item ids are unique only within their vault, so the vault id comes with it. */
export const onePasswordSource = (vaultId: string, itemId: string): string => `1password:${vaultId}/${itemId}`
/** True when a vault is wanted by id or name, recording which requested vaults it answers to. */
function matchVault(id: string, name: string, wanted: readonly string[], matched: Set<string>): boolean {
  if (wanted.length === 0) return true
  const hits = wanted.filter((value) => value === id || value === name)
  for (const hit of hits) matched.add(hit)
  return hits.length > 0
}

/**
 * Which fields an item's tags select under `--tag`: every field when it carries one of the tags, only the named ones
 * for `<tag>/<field>` tags, and undefined when it carries neither.
 */
function tagSelection(tags: readonly string[], wanted: readonly string[]): 'all' | readonly string[] | undefined {
  if (wanted.length === 0 || wanted.some((tag) => tags.includes(tag))) return 'all'
  const fields = tags.flatMap((value) =>
    wanted.flatMap((tag) => (value.startsWith(`${tag}/`) ? [value.slice(tag.length + 1)] : [])),
  )
  return fields.length === 0 ? undefined : [...new Set(fields)]
}

/** Narrows a mapped item to the fields its tags select, matched by stored name ignoring case, and drops the field tags. */
function selectFields(
  mapped: Omit<ImportItem, 'title'>,
  title: string,
  tags: readonly string[],
  wanted: readonly string[],
  warnings: string[],
): Omit<ImportItem, 'title'> | undefined {
  const selection = tagSelection(tags, wanted)
  // Listing and fetching aren't atomic: an item untagged in between is skipped, never imported whole.
  if (selection === undefined) {
    warnings.push(`${title}: skipped, it no longer carries the tag`)
    return undefined
  }
  const kept = tags.filter((value) => !wanted.some((tag) => value.startsWith(`${tag}/`)))
  if (selection === 'all') return { ...mapped, tags: kept }
  const fields: Record<string, string | Field> = {}
  for (const wanted of selection) {
    // Resolve the name against every mapped field, empty ones included, so an empty canonical field is never
    // stood in for by a custom one that differs only in case.
    const field = findField(mapped.fields, wanted)
    const value = field === undefined ? undefined : mapped.fields[field]
    if (field === undefined || value === undefined || value === '')
      warnings.push(`${title}: no single field "${wanted}" to import`)
    else fields[field] = value
  }
  if (Object.keys(fields).length === 0) {
    warnings.push(`${title}: skipped, none of its tagged fields were found`)
    return undefined
  }
  // The entry keeps its login-based name even when the username field itself isn't selected.
  return { ...mapped, fields, tags: kept, login: loginOf(mapped.fields) ?? '' }
}

export const spawnOp: RunOp = async (args, input) => {
  let child: Bun.Subprocess<'ignore' | Blob, 'pipe', 'pipe'>
  try {
    const stdin = input === undefined ? 'ignore' : new Blob([input])
    child = Bun.spawn(['op', ...args], { stdin, stdout: 'pipe', stderr: 'pipe' })
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      throw new TypeVaultError('unavailable', '1Password CLI (op) was not found; install it or use --via sdk')
    }
    throw error
  }
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  if (code !== 0) throw new TypeVaultError('unavailable', `op ${args[0]} ${args[1]} failed: ${stderr.trim()}`)
  return stdout
}

const SdkItemSchema = z.object({
  id: z.string().optional(),
  title: z.string(),
  category: z.string(),
  notes: z.string().default(''),
  tags: z.array(z.string()).default([]),
  websites: z.array(z.object({ url: z.string() })).default([]),
  fields: z
    .array(
      z.object({
        id: z.string().default(''),
        title: z.string().default(''),
        fieldType: z.string(),
        value: z.string().default(''),
        details: z
          .object({ type: z.string(), content: z.object({ publicKey: z.string().optional() }).optional() })
          .optional(),
      }),
    )
    .default([]),
})

async function readSdk(account: string, filters: Filters, connect: ConnectSdk, collected: Collected): Promise<void> {
  const client = await connect(account)
  const vaults = (await client.vaults.list()).filter((vault) =>
    matchVault(vault.id, vault.title, filters.vaults, collected.matchedVaults),
  )
  const { items, warnings } = collected
  const fetched = await mapLimit(vaults, CONCURRENCY, async (vault) => {
    const listed = (
      await client.items.list(vault.id, { type: 'ByState', content: { active: true, archived: false } })
    ).filter((item) => tagSelection(item.tags, filters.tags) !== undefined)
    if (listed.length === 0) return []
    const read = await client.items.getAll(
      vault.id,
      listed.map((item) => item.id),
    )
    return read.individualResponses
  })
  for (const [index, vault] of vaults.entries()) {
    for (const response of fetched[index] ?? []) {
      if (response.content === undefined) {
        warnings.push('skipped a 1Password item that could not be read')
        continue
      }
      const item = parseExternal(response.content, SdkItemSchema, '1Password SDK')
      const mapped = mapSdkItem(item)
      if (mapped === undefined) warnings.push(UNSUPPORTED)
      else {
        const selected = selectFields(mapped, item.title, item.tags, filters.tags, warnings)
        if (selected !== undefined)
          items.push({
            ...selected,
            title: item.title,
            ...(item.id === undefined ? {} : { source: onePasswordSource(vault.id, item.id) }),
          })
      }
    }
  }
}

function mapSdkItem(item: z.infer<typeof SdkItemSchema>): Omit<ImportItem, 'title'> | undefined {
  const mapped = mapSdkTemplate(item)
  if (mapped === undefined) return undefined
  const labeled = item.fields
    .filter((field) => SDK_TEXT_TYPES.has(field.fieldType))
    .map(
      (field) =>
        [
          field.title,
          {
            type:
              field.fieldType === 'Concealed'
                ? ('secret' as const)
                : field.fieldType === 'Totp'
                  ? ('totp' as const)
                  : ('text' as const),
            value: field.value,
          },
        ] as const,
    )
  return { ...mapped, fields: withCustomFields(mapped.fields, labeled) }
}

function mapSdkTemplate(item: z.infer<typeof SdkItemSchema>): Omit<ImportItem, 'title'> | undefined {
  const field = (match: (field: (typeof item.fields)[number]) => boolean) => item.fields.find(match)
  const named = (names: readonly string[]) =>
    field((value) => names.includes(value.id.toLowerCase()) || names.includes(value.title.toLowerCase()))?.value
  const url = item.websites[0]?.url
  switch (item.category) {
    case 'Login':
    case 'Password':
      return {
        preset: 'password',
        fields: {
          username: named(['username']),
          password: named(['password']),
          totp: field((value) => value.fieldType === 'Totp')?.value,
          url,
        },
        ...(url === undefined ? {} : { url }),
      }
    case 'SecureNote':
      return { preset: 'note', fields: { $default: item.notes } }
    case 'ApiCredentials':
      return { preset: 'api_key', fields: { $default: named(['credential', 'api key', 'api_key', 'key']) } }
    case 'SshKey': {
      const key = field((value) => value.fieldType === 'SshKey')
      return { preset: 'ssh', fields: { private_key: key?.value, public_key: key?.details?.content?.publicKey } }
    }
    default:
      return undefined
  }
}

/** A full 1Password SDK client through the desktop app, for reads and writes. */
export async function connectDesktop(account: string): Promise<Client> {
  // Loaded on demand: the SDK ships a large WebAssembly core that no other command needs.
  const sdk = await import('@1password/sdk')
  const { version } = z
    .object({ version: z.string() })
    .parse(await Bun.file(new URL('../../package.json', import.meta.url)).json())
  try {
    return await sdk.createClient({
      auth: new sdk.DesktopAuth(account),
      integrationName: 'typevault',
      integrationVersion: version,
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new TypeVaultError(
      'unavailable',
      `could not connect to the 1Password app (is Settings > Developer > Integrate with other apps on?): ${message}`,
    )
  }
}

const connectDesktopSdk: ConnectSdk = connectDesktop
