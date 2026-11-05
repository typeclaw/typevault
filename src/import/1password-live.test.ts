import { expect, test } from 'bun:test'

import { read1Password, type SdkClient } from './1password-live'

const OP_ITEMS: Readonly<Record<string, unknown>> = {
  login: {
    title: 'GitHub',
    category: 'LOGIN',
    vault: { name: 'Work' },
    tags: ['agent'],
    urls: [{ href: 'https://example.com/other' }, { href: 'https://example.com/login', primary: true }],
    fields: [
      { id: 'username', type: 'STRING', purpose: 'USERNAME', label: 'username', value: 'user@example.com' },
      { id: 'password', type: 'CONCEALED', purpose: 'PASSWORD', label: 'password', value: 'hunter2' },
      { id: 'one-time', type: 'OTP', label: 'one-time password', value: 'otpauth://totp/Example?secret=SEED' },
    ],
  },
  note: {
    title: 'Memo',
    category: 'SECURE_NOTE',
    vault: { name: 'Work' },
    fields: [{ id: 'notesPlain', type: 'STRING', purpose: 'NOTES', label: 'notesPlain', value: 'private note' }],
  },
  api: {
    title: 'API',
    category: 'API_CREDENTIAL',
    vault: { name: 'Work' },
    fields: [
      { id: 'credential', type: 'CONCEALED', label: 'credential', value: 'fake-key' },
      { id: 'custom1', type: 'CONCEALED', label: 'Webhook Secret', value: 'whsec' },
      { id: 'expires', type: 'DATE', label: 'expires', value: '1700000000' },
    ],
  },
  ssh: {
    title: 'SSH',
    category: 'SSH_KEY',
    vault: { name: 'Work' },
    fields: [
      {
        id: 'private_key',
        type: 'SSHKEY',
        label: 'private key',
        value: 'fake-pkcs8',
        ssh_formats: { openssh: { value: 'fake-openssh' } },
      },
      { id: 'public_key', type: 'STRING', label: 'public key', value: 'fake-public' },
    ],
  },
  card: { title: 'Card', category: 'CREDIT_CARD', vault: { name: 'Work' } },
}

test('op import reads every listed item and maps login, note, API, SSH, and tags', async () => {
  // given
  const calls: (readonly string[])[] = []
  const runOp = async (args: readonly string[]) => {
    calls.push(args)
    if (args[0] === 'vault')
      return JSON.stringify([
        { id: 'v1', name: 'Work' },
        { id: 'v2', name: 'Personal' },
      ])
    if (args[1] === 'list') return JSON.stringify(Object.keys(OP_ITEMS).map((id) => ({ id, vault: { id: 'v1' } })))
    return JSON.stringify(OP_ITEMS[args[2] ?? ''])
  }

  // when
  const result = await read1Password({ via: 'op', accounts: ['example'], vaults: ['Work'] }, { runOp })

  // then
  expect(result.entries.map((entry) => [String(entry.name), entry.fields])).toEqual([
    [
      'github/example-work',
      {
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'hunter2' },
        totp: { type: 'totp', value: 'otpauth://totp/Example?secret=SEED' },
        url: { type: 'text', value: 'https://example.com/login' },
      },
    ],
    ['memo/example-work', { $default: { type: 'secret', value: 'private note' } }],
    [
      'api/example-work',
      { $default: { type: 'secret', value: 'fake-key' }, 'Webhook Secret': { type: 'secret', value: 'whsec' } },
    ],
    [
      'ssh/example-work',
      { private_key: { type: 'secret', value: 'fake-openssh' }, public_key: { type: 'text', value: 'fake-public' } },
    ],
  ])
  expect(result.entries[0]?.tags).toEqual(['agent'])
  expect(result.entries[0]?.origin).toBe('https://example.com')
  expect(result.entries[0]?.source).toBe('1password:v1/login')
  expect(result.warnings).toEqual(['skipped unsupported 1Password item category'])
  expect(calls[0]).toEqual(['vault', 'list', '--format', 'json', '--account', 'example'])
  expect(calls[1]).toEqual(['item', 'list', '--format', 'json', '--vault', 'v1', '--account', 'example'])
  expect(calls[2]).toEqual([
    'item',
    'get',
    'login',
    '--vault',
    'v1',
    '--reveal',
    '--format',
    'json',
    '--account',
    'example',
  ])
})

test('op import with a tag imports whole items for the tag and only the named fields for <tag>/<field>', async () => {
  // given
  const calls: (readonly string[])[] = []
  const tags: Readonly<Record<string, readonly string[]>> = {
    login: ['agent', 'agent/password'],
    api: ['work', 'agent/webhook secret', 'agent/Missing'],
    note: ['agent/nested'],
    ssh: ['other'],
  }
  const listed = Object.entries(tags).map(([id, itemTags]) => ({ id, vault: { id: 'v1' }, tags: itemTags }))
  const runOp = async (args: readonly string[]) => {
    calls.push(args)
    if (args[0] === 'whoami') return JSON.stringify({ url: 'https://my.1password.com' })
    const id = args[2] ?? ''
    return JSON.stringify(args[1] === 'list' ? listed : { ...(OP_ITEMS[id] as object), tags: tags[id] })
  }

  // when
  const result = await read1Password({ via: 'op', tags: ['agent'] }, { runOp })

  // then
  expect(calls.filter((args) => args[0] === 'whoami')).toEqual([['whoami', '--format', 'json']])
  expect(calls.filter((args) => args[0] === 'item').map((args) => args.slice(0, 3))).toEqual([
    ['item', 'list', '--format'],
    ['item', 'get', 'login'],
    ['item', 'get', 'api'],
    ['item', 'get', 'note'],
  ])
  expect(calls[0]).toContain('--tags')
  expect(result.entries.map((entry) => [String(entry.name), entry.fields, entry.tags])).toEqual([
    [
      'github/my-work',
      {
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'hunter2' },
        totp: { type: 'totp', value: 'otpauth://totp/Example?secret=SEED' },
        url: { type: 'text', value: 'https://example.com/login' },
      },
      ['agent'],
    ],
    ['api/my-work', { 'Webhook Secret': { type: 'secret', value: 'whsec' } }, ['work']],
  ])
  expect(result.warnings).toEqual([
    'API: no single field "Missing" to import',
    'Memo: no single field "nested" to import',
    'Memo: skipped, none of its tagged fields were found',
  ])
})

test('op import never imports a whole item whose detail tags no longer select it', async () => {
  // given
  const runOp = async (args: readonly string[]) =>
    JSON.stringify(
      args[1] === 'list'
        ? [{ id: 'login', vault: { id: 'v1' }, tags: ['agent/username'] }]
        : { ...(OP_ITEMS['login'] as object), tags: [] },
    )

  // when
  const result = await read1Password({ via: 'op', tags: ['agent'] }, { runOp })

  // then
  expect(result.entries).toEqual([])
  expect(result.warnings).toEqual(['GitHub: skipped, it no longer carries the tag'])
})

test('op import prefers the exact field name and refuses an ambiguous one', async () => {
  // given
  const login = OP_ITEMS['login'] as { fields: readonly object[] }
  const item = {
    ...login,
    tags: ['agent/password', 'agent/region'],
    fields: [
      ...login.fields,
      { id: 'c1', type: 'CONCEALED', label: 'Password', value: 'custom-secret' },
      { id: 'c2', type: 'STRING', label: 'Region', value: 'us-east-1' },
      { id: 'c3', type: 'STRING', label: 'REGION', value: 'eu-west-1' },
    ],
  }
  const runOp = async (args: readonly string[]) =>
    JSON.stringify(
      args[0] === 'whoami'
        ? { url: 'my.1password.com' }
        : args[1] === 'list'
          ? [{ id: 'login', vault: { id: 'v1' }, tags: item.tags }]
          : item,
    )

  // when
  const result = await read1Password({ via: 'op', tags: ['agent'] }, { runOp })

  // then
  expect(result.entries.map((entry) => entry.fields)).toEqual([{ password: { type: 'secret', value: 'hunter2' } }])
  expect(result.warnings).toEqual(['GitHub: no single field "region" to import'])
})

test('op import never stands a custom field in for an empty canonical one', async () => {
  // given
  const login = OP_ITEMS['login'] as { fields: readonly { purpose?: string }[] }
  const item = {
    ...login,
    tags: ['agent/password'],
    fields: [
      ...login.fields.filter((field) => field.purpose !== 'PASSWORD'),
      { id: 'c1', type: 'CONCEALED', label: 'Password', value: 'custom-secret' },
    ],
  }
  const runOp = async (args: readonly string[]) =>
    JSON.stringify(args[1] === 'list' ? [{ id: 'login', vault: { id: 'v1' }, tags: item.tags }] : item)

  // when
  const result = await read1Password({ via: 'op', tags: ['agent'] }, { runOp })

  // then
  expect(result.entries).toEqual([])
  expect(result.warnings).toEqual([
    'GitHub: no single field "password" to import',
    'GitHub: skipped, none of its tagged fields were found',
  ])
})

test('op import reads each account and vault given, and every tag in one listing', async () => {
  // given
  const calls: (readonly string[])[] = []
  const vaults: Readonly<Record<string, readonly { id: string; name: string }[]>> = {
    work: [{ id: 'w1', name: 'Shared' }],
    home: [
      { id: 'h1', name: 'Shared' },
      { id: 'h2', name: 'Infra' },
      { id: 'h3', name: 'Other' },
    ],
  }
  const runOp = async (args: readonly string[]) => {
    calls.push(args)
    const account = args[args.indexOf('--account') + 1] ?? ''
    if (args[0] === 'vault') return JSON.stringify(vaults[account])
    if (args[1] === 'list') {
      const vault = args[args.indexOf('--vault') + 1] ?? ''
      return JSON.stringify([{ id: vault === 'w1' ? 'note' : 'api', vault: { id: vault }, tags: ['ci'] }])
    }
    return JSON.stringify({ ...(OP_ITEMS[args[2] ?? ''] as object), tags: ['ci'] })
  }

  // when
  const result = await read1Password(
    { via: 'op', accounts: ['work', 'home'], vaults: ['Shared', 'h2'], tags: ['agents', 'ci'] },
    { runOp },
  )

  // then
  expect(calls.filter((args) => args[1] === 'list').map((args) => args.join(' '))).toEqual([
    'vault list --format json --account work',
    'item list --format json --vault w1 --tags agents,ci --account work',
    'vault list --format json --account home',
    'item list --format json --vault h1 --tags agents,ci --account home',
    'item list --format json --vault h2 --tags agents,ci --account home',
  ])
  expect(result.entries.map((entry) => String(entry.name))).toEqual([
    'memo/work-work',
    'api/home-work',
    'api/home-work-2',
  ])
  expect(result.warnings).toEqual(['name collision: "api/home-work" renamed to "api/home-work-2"'])
})

test('op import fails when a vault is in none of the accounts, and refuses a comma in a tag', async () => {
  const runOp = async (args: readonly string[]) =>
    JSON.stringify(args[0] === 'vault' ? [{ id: 'v1', name: 'Work' }] : [])
  await expect(
    read1Password({ via: 'op', accounts: ['a', 'b'], vaults: ['Work', 'Missing'] }, { runOp }),
  ).rejects.toMatchObject({ code: 'not_found', message: '1Password vault "Missing" was not found' })
  await expect(read1Password({ via: 'op', tags: ['a,b'] }, { runOp })).rejects.toMatchObject({ code: 'invalid' })
})

test('op import rejects output that is not item JSON', async () => {
  await expect(read1Password({ via: 'op' }, { runOp: async () => 'not json' })).rejects.toMatchObject({
    code: 'invalid',
  })
})

function sdkClient(items: readonly unknown[], tags: readonly (readonly string[])[] = []): SdkClient {
  return {
    vaults: {
      list: async () => [
        { id: 'v1', title: 'Work' },
        { id: 'v2', title: 'Personal' },
      ],
    },
    items: {
      list: async (vaultId) =>
        vaultId === 'v1' ? items.map((_, index) => ({ id: String(index), tags: tags[index] ?? [] })) : [],
      getAll: async (_vaultId, ids) => ({
        individualResponses: ids.map((id) => {
          const content = items[Number(id)]
          return content === undefined ? { error: { type: 'itemNotFound' } } : { content }
        }),
      }),
    },
  }
}

test('sdk import maps desktop-app items and skips unreadable ones', async () => {
  // given
  const accounts: string[] = []
  const client = sdkClient([
    {
      id: 'login',
      title: 'GitHub',
      category: 'Login',
      tags: ['agent'],
      websites: [{ url: 'https://example.com/login' }],
      fields: [
        { id: 'username', title: 'username', fieldType: 'Text', value: 'user@example.com' },
        { id: 'password', title: 'password', fieldType: 'Concealed', value: 'hunter2' },
        { id: 'otp', title: 'one-time password', fieldType: 'Totp', value: 'otpauth://totp/Example?secret=SEED' },
      ],
    },
    { title: 'Memo', category: 'SecureNote', notes: 'private note', fields: [] },
    {
      title: 'API',
      category: 'ApiCredentials',
      fields: [
        { id: 'credential', title: 'credential', fieldType: 'Concealed', value: 'fake-key' },
        { id: 'custom1', title: 'Webhook Secret', fieldType: 'Concealed', value: 'whsec' },
        { id: 'expires', title: 'expires', fieldType: 'Date', value: '2026-01-01' },
      ],
    },
    {
      title: 'SSH',
      category: 'SshKey',
      fields: [
        {
          id: 'private_key',
          title: 'private key',
          fieldType: 'SshKey',
          value: 'fake-private',
          details: { type: 'SshKey', content: { publicKey: 'fake-public' } },
        },
      ],
    },
    { title: 'Card', category: 'CreditCard', fields: [] },
  ])
  const connectSdk = async (account: string) => {
    accounts.push(account)
    return {
      ...client,
      items: {
        ...client.items,
        getAll: async (vaultId: string, ids: string[]) => client.items.getAll(vaultId, [...ids, 'missing']),
      },
    }
  }

  // when
  const result = await read1Password({ via: 'sdk', accounts: ['Example'] }, { connectSdk })

  // then
  expect(accounts).toEqual(['Example'])
  expect(result.entries[0]?.source).toBe('1password:v1/login')
  expect(result.entries.map((entry) => [String(entry.name), entry.fields])).toEqual([
    [
      'github/example-work',
      {
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'hunter2' },
        totp: { type: 'totp', value: 'otpauth://totp/Example?secret=SEED' },
        url: { type: 'text', value: 'https://example.com/login' },
      },
    ],
    ['memo/example-work', { $default: { type: 'secret', value: 'private note' } }],
    [
      'api/example-work',
      { $default: { type: 'secret', value: 'fake-key' }, 'Webhook Secret': { type: 'secret', value: 'whsec' } },
    ],
    [
      'ssh/example-work',
      { private_key: { type: 'secret', value: 'fake-private' }, public_key: { type: 'text', value: 'fake-public' } },
    ],
  ])
  expect(result.warnings).toEqual([
    'skipped unsupported 1Password item category',
    'skipped a 1Password item that could not be read',
  ])
})

test('sdk import with a tag fetches items carrying the tag or a <tag>/<field> tag', async () => {
  // given
  const requested: string[][] = []
  const client = sdkClient(
    [
      { title: 'GitHub', category: 'Login', tags: ['agent'], fields: [] },
      {
        title: 'API',
        category: 'ApiCredentials',
        tags: ['agent/Webhook Secret'],
        fields: [
          { id: 'credential', title: 'credential', fieldType: 'Concealed', value: 'fake-key' },
          { id: 'custom1', title: 'Webhook Secret', fieldType: 'Concealed', value: 'whsec' },
        ],
      },
      { title: 'Other', category: 'SecureNote', notes: 'other note', fields: [] },
    ],
    [['agent'], ['agent/Webhook Secret'], ['other']],
  )
  const connectSdk = async () => ({
    ...client,
    items: {
      ...client.items,
      getAll: async (vaultId: string, ids: string[]) => {
        requested.push(ids)
        return client.items.getAll(vaultId, ids)
      },
    },
  })

  // when
  const result = await read1Password({ via: 'sdk', accounts: ['Example'], tags: ['agent'] }, { connectSdk })

  // then
  expect(requested).toEqual([['0', '1']])
  expect(result.entries.map((entry) => [String(entry.name), entry.fields, entry.tags])).toEqual([
    ['github/example-work', {}, ['agent']],
    ['api/example-work', { 'Webhook Secret': { type: 'secret', value: 'whsec' } }, []],
  ])
})

test('sdk import never imports a whole item whose detail tags no longer select it', async () => {
  // given
  const client = sdkClient(
    [
      {
        title: 'GitHub',
        category: 'Login',
        tags: [],
        fields: [{ id: 'password', title: 'password', fieldType: 'Concealed', value: 'hunter2' }],
      },
    ],
    [['agent/username']],
  )

  // when
  const result = await read1Password(
    { via: 'sdk', accounts: ['Example'], tags: ['agent'] },
    { connectSdk: async () => client },
  )

  // then
  expect(result.entries).toEqual([])
  expect(result.warnings).toEqual(['GitHub: skipped, it no longer carries the tag'])
})

test('sdk import reads every account given and finds a vault in any of them', async () => {
  // given
  const connected: string[] = []
  const work = sdkClient(
    [{ title: 'Memo', category: 'SecureNote', notes: 'work note', tags: ['ci'], fields: [] }],
    [['ci']],
  )
  const home = sdkClient(
    [{ title: 'Memo', category: 'SecureNote', notes: 'home note', tags: ['ops'], fields: [] }],
    [['ops']],
  )
  const connectSdk = async (account: string) => {
    connected.push(account)
    return account === 'Work' ? work : { ...home, vaults: { list: async () => [{ id: 'v1', title: 'Personal' }] } }
  }

  // when
  const result = await read1Password(
    { via: 'sdk', accounts: ['Work', 'Home'], vaults: ['Work', 'Personal'], tags: ['ci', 'ops'] },
    { connectSdk },
  )

  // then
  expect(connected).toEqual(['Work', 'Home'])
  expect(result.entries.map((entry) => [String(entry.name), entry.fields])).toEqual([
    ['memo/work-work', { $default: { type: 'secret', value: 'work note' } }],
    ['memo/home-personal', { $default: { type: 'secret', value: 'home note' } }],
  ])
})

test('sdk import keeps items whose account and vault names mix scripts', async () => {
  // given
  const client = sdkClient([{ title: 'GitHub', category: 'SecureNote', notes: 'note', fields: [] }])

  // when
  const result = await read1Password({ via: 'sdk', accounts: ['Работа'] }, { connectSdk: async () => client })

  // then
  expect(result.entries.map((entry): string => entry.name)).toEqual([expect.stringMatching(/^github\/[0-9a-f]{8}$/)])
  expect(result.warnings[0]).toContain('"Работа Work"')
})

test('sdk import needs an account and an existing vault', async () => {
  const connectSdk = async () => sdkClient([])
  await expect(read1Password({ via: 'sdk' }, { connectSdk })).rejects.toMatchObject({ code: 'invalid' })
  await expect(
    read1Password({ via: 'sdk', accounts: ['Example'], vaults: ['Missing'] }, { connectSdk }),
  ).rejects.toMatchObject({ code: 'not_found' })
})

test('op import fetches up to eight items at once and keeps them in listed order', async () => {
  // given: every item get waits until eight are in flight, then they finish in reverse
  const ids = Array.from({ length: 10 }, (_, index) => `item${index}`)
  let inFlight = 0
  let maxInFlight = 0
  const held: (() => void)[] = []
  const runOp = async (args: readonly string[]) => {
    if (args[1] === 'list') return JSON.stringify(ids.map((id) => ({ id, vault: { id: 'v1' } })))
    if (args[0] === 'whoami') return JSON.stringify({ url: 'https://my.1password.com' })
    inFlight += 1
    maxInFlight = Math.max(maxInFlight, inFlight)
    if (maxInFlight < 8) await new Promise<void>((resolve) => held.push(resolve))
    else for (const release of held.splice(0).reverse()) release()
    inFlight -= 1
    const title = `Note ${args[2]?.slice('item'.length)}`
    return JSON.stringify({ title, category: 'PASSWORD', vault: { name: 'Work' } })
  }

  // when
  const result = await read1Password({ via: 'op' }, { runOp })

  // then
  expect(maxInFlight).toBe(8)
  expect(result.entries.map((entry) => String(entry.name))).toEqual(ids.map((_, index) => `note-${index}/my-work`))
})

test('op import starts no more item fetches once one fails', async () => {
  // given: eight fetches start and hold, then the first one fails
  const ids = Array.from({ length: 10 }, (_, index) => `item${index}`)
  const started: string[] = []
  const held: (() => void)[] = []
  let fail: (error: Error) => void = () => {}
  const runOp = async (args: readonly string[]) => {
    if (args[1] === 'list') return JSON.stringify(ids.map((id) => ({ id, vault: { id: 'v1' } })))
    started.push(args[2] ?? '')
    const done = new Promise<void>((resolve, reject) => {
      if (args[2] === 'item0') fail = reject
      else held.push(resolve)
    })
    if (started.length === 8) fail(new Error('op item get failed'))
    await done
    return JSON.stringify({ title: args[2], category: 'PASSWORD', vault: { name: 'Work' } })
  }

  // when
  const result = read1Password({ via: 'op' }, { runOp })

  // then
  await expect(result).rejects.toThrow('op item get failed')
  for (const release of held) release()
  // Let the released fetches settle: every pending microtask runs before the next macrotask.
  await new Promise((resolve) => setImmediate(resolve))
  expect(started).toEqual(ids.slice(0, 8))
})
