import { expect, test } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { export1Password, type KeyItem, type SdkWriter } from './1password'

const ITEM: KeyItem = {
  title: 'TypeVault member abc',
  credential: 'tvk1:fake-secret',
  details: { 'vault id': 'abc', role: 'tier', tier: 'member', generation: '2' },
}

type OpCall = { readonly args: readonly string[]; readonly input?: string }

function fakeOp(existing: readonly { id: string; title: string }[], accounts = 1) {
  const calls: OpCall[] = []
  const runOp = async (args: readonly string[], input?: string): Promise<string> => {
    calls.push(input === undefined ? { args } : { args, input })
    if (args[0] === 'account') return JSON.stringify(Array.from({ length: accounts }, () => ({})))
    if (args[1] === 'list') return JSON.stringify(existing)
    return '{}'
  }
  return { calls, runOp }
}

test('op export pipes an API Credential template through stdin, never the key in argv', async () => {
  // given op with one signed-in account and no matching item
  const op = fakeOp([{ id: 'other', title: 'Unrelated' }])

  // when a tier key is exported
  const via = await export1Password(ITEM, { vault: 'Infra' }, { runOp: op.runOp, hasOp: () => true })

  // then op creates one item from stdin and archives nothing
  expect(via).toBe('op')
  expect(op.calls.map((call) => call.args.slice(0, 2))).toEqual([
    ['account', 'list'],
    ['item', 'list'],
    ['item', 'create'],
  ])
  expect(op.calls.flatMap((call) => call.args).join(' ')).not.toContain(ITEM.credential)
  const template = JSON.parse(op.calls[2]?.input ?? '')
  expect(template).toMatchObject({ title: ITEM.title, category: 'API_CREDENTIAL', tags: ['typevault'] })
  expect(template.fields[0]).toEqual({
    id: 'credential',
    label: 'credential',
    type: 'CONCEALED',
    value: ITEM.credential,
  })
  expect(template.fields).toContainEqual({ id: 'vault_id', label: 'vault id', type: 'STRING', value: 'abc' })
})

test('op export refuses an existing title without --replace', async () => {
  const op = fakeOp([{ id: 'old', title: ITEM.title }])

  const result = export1Password(ITEM, { vault: 'Infra', account: 'acme' }, { runOp: op.runOp, hasOp: () => true })

  await expect(result).rejects.toMatchObject({ code: 'conflict' })
  expect(op.calls.some((call) => call.args[1] === 'create')).toBe(false)
})

test('op export with --replace archives the old item only after creating the new one', async () => {
  const op = fakeOp([{ id: 'old', title: ITEM.title }])

  await export1Password(
    ITEM,
    { vault: 'Infra', account: 'acme', replace: true },
    { runOp: op.runOp, hasOp: () => true },
  )

  expect(op.calls.map((call) => call.args.slice(0, 3))).toEqual([
    ['item', 'list', '--format'],
    ['item', 'create', '-'],
    ['item', 'delete', 'old'],
  ])
  expect(op.calls[2]?.args).toContain('--archive')
})

test('op export without --account refuses when several accounts are signed in', async () => {
  const op = fakeOp([], 2)

  const result = export1Password(ITEM, { vault: 'Infra' }, { runOp: op.runOp, hasOp: () => true })

  await expect(result).rejects.toBeInstanceOf(TypeVaultError)
  expect(op.calls).toHaveLength(1)
})

test('without op installed, export falls back to the SDK and replaces by archiving', async () => {
  // given an SDK vault holding an item with the same title
  const created: unknown[] = []
  const archived: string[] = []
  const client: SdkWriter = {
    vaults: { list: async () => [{ id: 'v1', title: 'Infra' }] },
    items: {
      list: async () => [{ id: 'old', title: ITEM.title }],
      create: async (params) => created.push(params),
      archive: async (_vault, item) => {
        archived.push(item)
      },
    },
  }

  // when exporting with --replace and no transport chosen
  const via = await export1Password(
    ITEM,
    { vault: 'Infra', account: 'acme', replace: true },
    { connect: async () => client, hasOp: () => false },
  )

  // then the SDK stores a concealed credential and archives the old item
  expect(via).toBe('sdk')
  expect(created).toEqual([
    {
      vaultId: 'v1',
      title: ITEM.title,
      tags: ['typevault'],
      fields: [
        { id: 'credential', title: 'credential', value: ITEM.credential, concealed: true },
        { id: 'vault_id', title: 'vault id', value: 'abc', concealed: false },
        { id: 'role', title: 'role', value: 'tier', concealed: false },
        { id: 'tier', title: 'tier', value: 'member', concealed: false },
        { id: 'generation', title: 'generation', value: '2', concealed: false },
      ],
    },
  ])
  expect(archived).toEqual(['old'])
})

function recordingSdk(vaults: readonly { id: string; title: string }[]) {
  const created: { vaultId: string }[] = []
  const client: SdkWriter = {
    vaults: { list: async () => vaults },
    items: {
      list: async () => [],
      create: async (params) => created.push(params),
      archive: async () => {},
    },
  }
  return { created, connect: async () => client }
}

test('SDK export refuses a vault title shared by several vaults', async () => {
  const sdk = recordingSdk([
    { id: 'v1', title: 'Backup' },
    { id: 'v2', title: 'Backup' },
  ])

  const result = export1Password(ITEM, { vault: 'Backup', account: 'acme', via: 'sdk' }, { connect: sdk.connect })

  await expect(result).rejects.toMatchObject({ code: 'conflict' })
  expect(sdk.created).toEqual([])
})

test('SDK export prefers a vault id over another vault titled the same', async () => {
  const sdk = recordingSdk([
    { id: 'other', title: 'v2' },
    { id: 'v2', title: 'Backup' },
  ])

  await export1Password(ITEM, { vault: 'v2', account: 'acme', via: 'sdk' }, { connect: sdk.connect })

  expect(sdk.created.map((params) => params.vaultId)).toEqual(['v2'])
})

test('SDK export needs an account', async () => {
  const result = export1Password(ITEM, { vault: 'Infra', via: 'sdk' }, { connect: async () => ({}) as SdkWriter })

  await expect(result).rejects.toMatchObject({ code: 'invalid' })
})
