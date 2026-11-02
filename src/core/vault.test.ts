import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from './admin'
import { decodeSecretKey, type SecretKey } from './crypto'
import { signerOf } from './entries'
import { TypeVaultError } from './errors'
import { initVault } from './init'
import { parseEntryName } from './naming'
import { Vault } from './vault'

let root: string
let operator: SecretKey
let admin: Admin

const env = {}
const open = (keys: readonly SecretKey[]): Promise<Vault> => Vault.open(root, keys, env)
const keyOf = async (group: string): Promise<SecretKey> => decodeSecretKey(await admin.exportKey(group))
const stripe = {
  name: parseEntryName('stripe'),
  type: 'api_key',
  fields: { key: 'sk_test_123' },
  group: 'member',
} as const

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'typevault-'))
  operator = await initVault(root)
  admin = new Admin(await open([operator]))
  await admin.addGroup('guest')
  await admin.addGroup('member')
  await admin.addGroup('trusted')
  await admin.include('member', 'guest')
  await admin.include('trusted', 'member')
})

afterEach(() => rmSync(root, { recursive: true, force: true }))

describe('group access', () => {
  it('lets a group key read entries of the groups it includes, transitively', async () => {
    await (await open([operator])).put(stripe, signerOf(operator))
    const trusted = await open([await keyOf('trusted')])
    expect((await trusted.find(stripe.name))?.payload.fields).toEqual({ key: 'sk_test_123' })
  })

  it('hides entries of groups a key does not reach', async () => {
    await (await open([operator])).put(stripe, signerOf(operator))
    const guest = await open([await keyOf('guest')])
    expect(await guest.find(stripe.name)).toBeUndefined()
  })

  it('refuses a write signed by a group key that does not reach the target group', async () => {
    const guestKey = await keyOf('guest')
    const guest = await open([guestKey])
    expect(guest.put(stripe, signerOf(guestKey))).rejects.toThrow(TypeVaultError)
  })

  it('accepts a write signed by an including group key', async () => {
    const trustedKey = await keyOf('trusted')
    await (await open([trustedKey])).put(stripe, signerOf(trustedKey))
    expect((await (await open([await keyOf('member')])).find(stripe.name))?.envelope.rev).toBe(1)
  })
})

describe('integrity', () => {
  it('reports a tampered entry instead of returning it', async () => {
    const vault = await open([operator])
    const { envelope } = await vault.put(stripe, signerOf(operator))
    const file = join(root, 'vault', 'entries', `${envelope.id}.json`)
    writeFileSync(file, readFileSync(file, 'utf8').replace('"rev": 1', '"rev": 7'))
    const scan = await vault.scan()
    expect(scan.entries).toHaveLength(0)
    expect(scan.problems).toEqual([{ file: `${envelope.id}.json`, reason: 'bad signature' }])
  })

  it('contains a validly signed but undecryptable entry instead of failing every scan', async () => {
    const vault = await open([operator])
    await vault.put(stripe, signerOf(operator))
    await vault.putCiphertext(parseEntryName('junk'), 'member', new Uint8Array([1, 2, 3]), signerOf(operator))
    const scan = await vault.scan()
    expect(scan.entries.map((entry): string => entry.payload.name)).toEqual(['stripe'])
    expect(scan.problems).toHaveLength(1)
  })

  it('refuses to store a field the entry type does not have', async () => {
    const vault = await open([operator])
    expect(
      vault.put({ ...stripe, fields: { key: 'x', external_diff: 'sh' } }, signerOf(operator)),
    ).rejects.toMatchObject({ code: 'invalid' })
  })

  it('never lets a lower group shadow a name held by a higher group', async () => {
    const vault = await open([operator])
    await vault.put({ ...stripe, group: 'trusted' }, signerOf(operator))
    const guestKey = await keyOf('guest')
    const guest = await open([guestKey])
    await guest.put({ ...stripe, group: 'guest', fields: { key: 'ATTACKER' } }, signerOf(guestKey))
    expect((await open([await keyOf('trusted')])).find(stripe.name)).resolves.toMatchObject({
      payload: { fields: { key: 'sk_test_123' } },
    })
  })

  it('reports an entry swapped back to an older signed revision', async () => {
    const vault = await open([operator])
    const first = await vault.put(stripe, signerOf(operator))
    await vault.scan()
    await vault.put({ ...stripe, fields: { key: 'sk_test_456' } }, signerOf(operator))
    await vault.scan()
    const file = join(root, 'vault', 'entries', `${first.envelope.id}.json`)
    writeFileSync(file, JSON.stringify(first.envelope))
    const scan = await vault.scan()
    expect(scan.entries).toHaveLength(0)
    expect(scan.problems[0]?.reason).toContain('rolled back')
  })

  it('rejects a vault whose operator key changed after it was first trusted', async () => {
    const file = join(root, 'vault', 'operator.json')
    const doc = JSON.parse(readFileSync(file, 'utf8'))
    writeFileSync(file, JSON.stringify({ ...doc, signPublic: 'AAAA' }))
    expect(open([operator])).rejects.toMatchObject({ code: 'tampered' })
  })

  it('rejects a stale revision on compare-and-swap', async () => {
    const vault = await open([operator])
    await vault.put(stripe, signerOf(operator))
    expect(vault.put(stripe, signerOf(operator), { ifRev: 0 })).rejects.toMatchObject({ code: 'conflict' })
    expect((await vault.put(stripe, signerOf(operator), { ifRev: 1 })).envelope.rev).toBe(2)
  })

  it('serializes concurrent writes from one process', async () => {
    const vault = await open([operator])
    const names = ['a', 'b', 'c', 'd'].map((name) => ({ ...stripe, name: parseEntryName(name) }))
    await Promise.all(names.map((input) => vault.put(input, signerOf(operator))))
    expect((await vault.scan()).entries.map((entry): string => entry.payload.name).sort()).toEqual(['a', 'b', 'c', 'd'])
  })
})

describe('rotation', () => {
  it('locks out the old key, keeps includers working and flags reachable entries', async () => {
    await (await open([operator])).put(stripe, signerOf(operator))
    const oldMember = await keyOf('member')
    expect(await admin.rotate('member')).toEqual(['stripe'])
    expect(await (await open([oldMember])).find(stripe.name)).toBeUndefined()
    const viaTrusted = await (await open([await keyOf('trusted')])).find(stripe.name)
    expect(viaTrusted?.payload.needsRotation).toBe(true)
  })

  it('clears the rotation flag when the value is re-set', async () => {
    const vault = await open([operator])
    await vault.put(stripe, signerOf(operator))
    await admin.rotate('member')
    const reset = await vault.put({ ...stripe, fields: { key: 'sk_test_456' } }, signerOf(operator))
    expect(reset.payload.needsRotation).toBeUndefined()
  })

  it('stops an excluded group from reaching the formerly included one', async () => {
    await (await open([operator])).put(stripe, signerOf(operator))
    const trustedKey = await keyOf('trusted')
    await admin.exclude('trusted', 'member')
    expect(await (await open([trustedKey])).find(stripe.name)).toBeUndefined()
  })

  it('refuses an include that would form a cycle', async () => {
    expect(admin.include('guest', 'trusted')).rejects.toMatchObject({ code: 'invalid' })
  })

  it('leaves no staged transaction behind', async () => {
    await admin.rotate('trusted')
    expect(readdirSync(join(root, 'run', 'txn'))).toEqual([])
  })
})
