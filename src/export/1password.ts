import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { connectDesktop, type OnePasswordVia, type RunOp, spawnOp } from '../import/1password-live'
import { parseJson } from '../import/shared'

export type KeyItem = {
  readonly title: string
  readonly credential: string
  readonly details: Readonly<Record<string, string>>
}

export type ExportOptions = {
  /** Unset picks whatever is reachable: the `op` CLI when installed, else the desktop SDK. */
  readonly via?: OnePasswordVia
  readonly account?: string
  readonly vault: string
  readonly replace?: boolean
}

type WriterField = { readonly id: string; readonly title: string; readonly value: string; readonly concealed: boolean }

export type SdkWriter = {
  readonly vaults: { list(): Promise<readonly { readonly id: string; readonly title: string }[]> }
  readonly items: {
    list(vaultId: string): Promise<readonly { readonly id: string; readonly title: string }[]>
    create(params: { vaultId: string; title: string; tags: string[]; fields: WriterField[] }): Promise<unknown>
    archive(vaultId: string, itemId: string): Promise<void>
  }
}

export type ConnectWriter = (account: string) => Promise<SdkWriter>

export const EXPORT_TAG = 'typevault'

export const identityTitle = (name: string): string => `TypeVault identity ${name}`

/** Stores `item` in 1Password and returns the transport used. Archives replaced items only after the new one exists. */
export async function export1Password(
  item: KeyItem,
  options: ExportOptions,
  deps: {
    readonly runOp?: RunOp
    readonly connect?: ConnectWriter
    readonly hasOp?: () => boolean
  } = {},
): Promise<OnePasswordVia> {
  const via = options.via ?? ((deps.hasOp ?? (() => Bun.which('op') !== null))() ? 'op' : 'sdk')
  if (via === 'op') await exportOp(item, options, deps.runOp ?? spawnOp)
  else {
    if (options.account === undefined) {
      throw new TypeVaultError('invalid', '--account is required with --via sdk (the account name shown in 1Password)')
    }
    await exportSdk(item, options, await (deps.connect ?? connectWriter)(options.account))
  }
  return via
}

const fieldsOf = (item: KeyItem): WriterField[] => [
  { id: 'credential', title: 'credential', value: item.credential, concealed: true },
  ...Object.entries(item.details).map(([title, value]) => ({
    id: title.replaceAll(' ', '_'),
    title,
    value,
    concealed: false,
  })),
]

const refuseExisting = (item: KeyItem, vault: string): never => {
  throw new TypeVaultError(
    'conflict',
    `1Password vault "${vault}" already has "${item.title}"; pass --replace to archive it and store the new key`,
  )
}

const OpAccountsSchema = z.array(z.object({}).loose())
const OpItemsSchema = z.array(z.object({ id: z.string(), title: z.string() }))
const OpVaultsSchema = z.array(z.object({ id: z.string(), name: z.string() }))

async function exportOp(item: KeyItem, options: ExportOptions, runOp: RunOp): Promise<void> {
  if (options.account === undefined) {
    const accounts = parseJson(await runOp(['account', 'list', '--format', 'json']), OpAccountsSchema, 'op')
    // With several accounts, op's default is easy to forget: a key must never land in the wrong one.
    if (accounts.length > 1) {
      throw new TypeVaultError('invalid', 'several 1Password accounts are signed in; pass --account')
    }
  }
  const account = options.account === undefined ? [] : ['--account', options.account]
  const vaults = parseJson(await runOp(['vault', 'list', '--format', 'json', ...account]), OpVaultsSchema, 'op')
  const vault = resolveVault(
    vaults.map(({ id, name }) => ({ id, title: name })),
    options.vault,
  )
  const scope = ['--vault', vault.id, ...account]
  const listed = parseJson(await runOp(['item', 'list', '--format', 'json', ...scope]), OpItemsSchema, 'op')
  const existing = listed.filter((entry) => entry.title === item.title)
  if (existing.length > 0 && options.replace !== true) refuseExisting(item, options.vault)
  const template = {
    title: item.title,
    category: 'API_CREDENTIAL',
    tags: [EXPORT_TAG],
    fields: fieldsOf(item).map((field) => ({
      id: field.id,
      label: field.title,
      type: field.concealed ? 'CONCEALED' : 'STRING',
      value: field.value,
    })),
  }
  // The template goes through stdin: the key never appears in argv, where other processes could read it.
  await runOp(['item', 'create', '-', '--format', 'json', ...scope], JSON.stringify(template))
  for (const entry of existing) await runOp(['item', 'delete', entry.id, '--archive', ...scope])
}

async function exportSdk(item: KeyItem, options: ExportOptions, client: SdkWriter): Promise<void> {
  const vault = resolveVault(await client.vaults.list(), options.vault)
  const existing = (await client.items.list(vault.id)).filter((entry) => entry.title === item.title)
  if (existing.length > 0 && options.replace !== true) refuseExisting(item, options.vault)
  await client.items.create({ vaultId: vault.id, title: item.title, tags: [EXPORT_TAG], fields: fieldsOf(item) })
  for (const entry of existing) await client.items.archive(vault.id, entry.id)
}

function resolveVault<V extends { readonly id: string; readonly title: string }>(
  vaults: readonly V[],
  wanted: string,
): V {
  const byId = vaults.find((vault) => vault.id === wanted)
  if (byId !== undefined) return byId
  const byTitle = vaults.filter((vault) => vault.title === wanted)
  const [only] = byTitle
  if (only === undefined) throw new TypeVaultError('not_found', `1Password vault "${wanted}" was not found`)
  // A key must never land in a vault picked by list order, which may be one shared with other people.
  if (byTitle.length > 1) {
    throw new TypeVaultError('conflict', `several 1Password vaults are named "${wanted}"; pass the vault id instead`)
  }
  return only
}

const connectWriter: ConnectWriter = async (account) => {
  const sdk = await import('@1password/sdk')
  const client = await connectDesktop(account)
  return {
    vaults: client.vaults,
    items: {
      list: (vaultId) => client.items.list(vaultId),
      create: (params) =>
        client.items.create({
          ...params,
          category: sdk.ItemCategory.ApiCredentials,
          fields: params.fields.map(({ concealed, ...field }) => ({
            ...field,
            fieldType: concealed ? sdk.ItemFieldType.Concealed : sdk.ItemFieldType.Text,
          })),
        }),
      archive: (vaultId, itemId) => client.items.archive(vaultId, itemId),
    },
  }
}
