import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { collectEntries, parseExternal, parseJson, withCustomFields, type ImportItem } from './shared'
import type { ImportResult } from './types'

export const ONEPASSWORD_VIAS = ['sdk', 'op'] as const
export type OnePasswordVia = (typeof ONEPASSWORD_VIAS)[number]

export type OnePasswordOptions = {
  readonly via: OnePasswordVia
  readonly account?: string
  readonly vault?: string
  readonly tag?: string
}

export type RunOp = (args: readonly string[]) => Promise<string>

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
// Field types kept as custom fields; dates, menus, addresses and keys don't read as one string.
const OP_TEXT_TYPES: ReadonlySet<string> = new Set(['STRING', 'CONCEALED', 'URL', 'EMAIL', 'PHONE'])
const SDK_TEXT_TYPES: ReadonlySet<string> = new Set(['Text', 'Concealed', 'Url', 'Email', 'Phone'])

export async function read1Password(
  options: OnePasswordOptions,
  deps: { readonly runOp?: RunOp; readonly connectSdk?: ConnectSdk } = {},
): Promise<ImportResult> {
  if (options.via === 'op') return readOp(options, deps.runOp ?? spawnOp)
  if (options.account === undefined) {
    throw new TypeVaultError('invalid', '--account is required with --via sdk (the account name shown in 1Password)')
  }
  return readSdk(options.account, options, deps.connectSdk ?? connectDesktopSdk)
}

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

async function readOp(options: OnePasswordOptions, runOp: RunOp): Promise<ImportResult> {
  const account = options.account === undefined ? [] : ['--account', options.account]
  const vault = options.vault === undefined ? [] : ['--vault', options.vault]
  const tag = options.tag === undefined ? [] : ['--tags', options.tag]
  const listed = parseJson(
    await runOp(['item', 'list', '--format', 'json', ...vault, ...tag, ...account]),
    OpListSchema,
    'op',
  )
  const items: ImportItem[] = []
  const warnings: string[] = []
  // `op --tags` also matches nested tags (`tag/child`); keep only exact matches, like the SDK path.
  for (const entry of listed.filter((item) => hasTag(item.tags, options.tag))) {
    const args = ['item', 'get', entry.id, '--vault', entry.vault.id, '--reveal', '--format', 'json', ...account]
    const item = parseJson(await runOp(args), OpItemSchema, 'op')
    const mapped = mapOpItem(item)
    if (mapped === undefined) warnings.push(UNSUPPORTED)
    else items.push({ ...mapped, title: item.title, container: item.vault.name, tags: item.tags })
  }
  return collectEntries(items, warnings)
}

function mapOpItem(item: z.infer<typeof OpItemSchema>): Omit<ImportItem, 'title'> | undefined {
  const mapped = mapOpTemplate(item)
  if (mapped === undefined) return undefined
  // Built-in fields (username, password, notes) carry a purpose; custom ones don't.
  const labeled = item.fields
    .filter((field) => field.purpose === undefined && OP_TEXT_TYPES.has(field.type))
    .map((field) => [field.label, field.value] as const)
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
        type: 'password',
        fields: {
          username: value((field) => field.purpose === 'USERNAME'),
          password: value((field) => field.purpose === 'PASSWORD'),
          totp: value((field) => field.type === 'OTP'),
          url,
        },
        ...(url === undefined ? {} : { url }),
      }
    case 'SECURE_NOTE':
      return { type: 'note', fields: { text: value((field) => field.purpose === 'NOTES') } }
    case 'API_CREDENTIAL':
      return { type: 'api_key', fields: { key: named(['credential', 'api key', 'api_key', 'key']) } }
    case 'SSH_KEY': {
      const key = item.fields.find((field) => field.type === 'SSHKEY')
      return {
        type: 'ssh',
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

function hasTag(tags: readonly string[], tag: string | undefined): boolean {
  return tag === undefined || tags.includes(tag)
}

const spawnOp: RunOp = async (args) => {
  let child: Bun.Subprocess<'ignore', 'pipe', 'pipe'>
  try {
    child = Bun.spawn(['op', ...args], { stdin: 'ignore', stdout: 'pipe', stderr: 'pipe' })
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

async function readSdk(account: string, options: OnePasswordOptions, connect: ConnectSdk): Promise<ImportResult> {
  const only = options.vault
  const client = await connect(account)
  const vaults = (await client.vaults.list()).filter(
    (vault) => only === undefined || vault.id === only || vault.title === only,
  )
  if (only !== undefined && vaults.length === 0)
    throw new TypeVaultError('not_found', `1Password vault "${only}" was not found`)
  const items: ImportItem[] = []
  const warnings: string[] = []
  for (const vault of vaults) {
    const listed = (
      await client.items.list(vault.id, { type: 'ByState', content: { active: true, archived: false } })
    ).filter((item) => hasTag(item.tags, options.tag))
    if (listed.length === 0) continue
    const fetched = await client.items.getAll(
      vault.id,
      listed.map((item) => item.id),
    )
    for (const response of fetched.individualResponses) {
      if (response.content === undefined) {
        warnings.push('skipped a 1Password item that could not be read')
        continue
      }
      const item = parseExternal(response.content, SdkItemSchema, '1Password SDK')
      const mapped = mapSdkItem(item)
      if (mapped === undefined) warnings.push(UNSUPPORTED)
      else items.push({ ...mapped, title: item.title, container: vault.title, tags: item.tags })
    }
  }
  return collectEntries(items, warnings)
}

function mapSdkItem(item: z.infer<typeof SdkItemSchema>): Omit<ImportItem, 'title'> | undefined {
  const mapped = mapSdkTemplate(item)
  if (mapped === undefined) return undefined
  const labeled = item.fields
    .filter((field) => SDK_TEXT_TYPES.has(field.fieldType))
    .map((field) => [field.title, field.value] as const)
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
        type: 'password',
        fields: {
          username: named(['username']),
          password: named(['password']),
          totp: field((value) => value.fieldType === 'Totp')?.value,
          url,
        },
        ...(url === undefined ? {} : { url }),
      }
    case 'SecureNote':
      return { type: 'note', fields: { text: item.notes } }
    case 'ApiCredentials':
      return { type: 'api_key', fields: { key: named(['credential', 'api key', 'api_key', 'key']) } }
    case 'SshKey': {
      const key = field((value) => value.fieldType === 'SshKey')
      return { type: 'ssh', fields: { private_key: key?.value, public_key: key?.details?.content?.publicKey } }
    }
    default:
      return undefined
  }
}

const connectDesktopSdk: ConnectSdk = async (account) => {
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
