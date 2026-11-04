import { afterEach, beforeEach, expect, it, spyOn } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from './admin'
import { type SecretKey, unseal } from './crypto'
import { fromBase64 } from './encoding'
import { type Envelope, signerOf } from './entries'
import { createIdentity } from './identity'
import { founderOf, initGlobalVault } from './init'
import { globalLayout } from './layout'
import { parseEntryName } from './naming'
import { Txn } from './txn'
import { Vault } from './vault'

const envIn = (dir: string) => ({ TYPEVAULT_DIR: join(dir, 'vault'), XDG_CONFIG_HOME: dir })

let root: string
let owner: SecretKey
let admin: Admin

const open = (keys: readonly SecretKey[]): Promise<Vault> => Vault.open(globalLayout(envIn(root)), keys, {})
const put = async (name: string, tier: string): Promise<Envelope> =>
  (
    await (
      await open([owner])
    ).put(
      { name: parseEntryName(name), fields: { key: { type: 'secret' as const, value: `${name}-secret` } }, tier },
      signerOf(owner),
    )
  ).envelope

async function addMachine(name: string, tiers: readonly string[]): Promise<SecretKey> {
  const { identity, key } = await createIdentity(name, 'machine')
  const { member } = founderOf(identity)
  await admin.addMember(name, { ...member, owner: false, tiers })
  return key
}

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'typevault-members-'))
  const founder = await createIdentity('alice', 'human', 'correct horse')
  ;({ owner } = await initGlobalVault(founderOf(founder.identity), envIn(root)))
  admin = new Admin(await open([founder.key]))
  await admin.addTier('member')
  await admin.addTier('trusted')
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

it("gives an owner member's key the owner key", async () => {
  const { identity, key } = await createIdentity('bob', 'human', 'pw')
  await admin.addMember('bob', { ...founderOf(identity).member, owner: true, tiers: [] })

  expect((await open([key])).keyring.owner).toBeDefined()
})

it('lets a member read only the tiers it was given', async () => {
  // given entries in two tiers
  await put('openai', 'member')
  await put('stripe', 'trusted')

  // when a machine joins with the member tier
  const key = await addMachine('ci', ['member'])

  // then it reads that tier only
  const { entries } = await (await open([key])).scan()
  expect(entries.map((entry): string => entry.payload.name)).toEqual(['openai'])
})

it("keeps ciphertext from before a member joined out of the member's reach", async () => {
  // given an entry written before the member joins, as git history keeps it
  const before = await put('openai', 'member')

  // when the member joins
  const key = await addMachine('ci', ['member'])

  // then the tier was rotated, and the new key can't open the old ciphertext
  const tierKey = await (await open([key])).keyring.unlock('member')
  if (tierKey === undefined) throw new Error('member key does not reach the tier')
  expect(tierKey.role).toMatchObject({ kind: 'tier', gen: 2 })
  await expect(unseal([tierKey.identity], fromBase64(before.payload))).rejects.toMatchObject({ code: 'denied' })
})

it("keeps an included tier's ciphertext from before the include out of the includer's reach", async () => {
  // given a member of one tier, and an entry in another tier, as git history keeps it
  const key = await addMachine('ci', ['trusted'])
  const before = await put('openai', 'member')

  // when its tier starts including the other
  await admin.include('trusted', 'member')

  // then the included tier was rotated, and the key it now reaches can't open the old ciphertext
  const tierKey = await (await open([key])).keyring.unlock('member')
  if (tierKey === undefined) throw new Error('includer does not reach the included tier')
  expect(tierKey.role).toMatchObject({ kind: 'tier', gen: 2 })
  await expect(unseal([tierKey.identity], fromBase64(before.payload))).rejects.toMatchObject({ code: 'denied' })
})

it('locks a removed member out and lists what it could read for rotation', async () => {
  // given a member that could read one entry
  await put('openai', 'member')
  await put('stripe', 'trusted')
  const key = await addMachine('ci', ['member'])

  // when it is removed
  const affected = await admin.removeMember('ci')

  // then its key opens nothing, and only what it reached needs rotating at the source
  expect(affected).toEqual(['openai'])
  expect((await (await open([key])).scan()).entries).toEqual([])
  expect(Object.keys((await open([])).state.members)).toEqual(['alice'])
})

it('refuses to remove an owner', async () => {
  await expect(admin.removeMember('alice')).rejects.toMatchObject({ code: 'invalid' })
})

it('commits a human founder only in sealed form', async () => {
  const committed = readFileSync(join(globalLayout(envIn(root)).membersDir, 'alice.key'), 'utf8')

  expect(JSON.parse(committed)).toMatchObject({ v: 1, kdf: { name: 'argon2id' } })
})

it('keeps a removal all-or-nothing when its transaction fails before committing', async () => {
  // given a member holding a tier that includes another
  await admin.include('trusted', 'member')
  await put('openai', 'member')
  const key = await addMachine('ci', ['trusted'])
  const before = (await open([])).state

  // when the rotation fails after the membership change was staged
  const put_ = Txn.prototype.put
  const failing = spyOn(Txn.prototype, 'put').mockImplementation(function (this: Txn, rel, data) {
    if (rel === 'tiers.json') throw new Error('disk full')
    return put_.call(this, rel, data)
  })
  try {
    await expect(admin.removeMember('ci')).rejects.toThrow('disk full')
  } finally {
    failing.mockRestore()
  }

  // then nothing was published: still a member, same generations, and its key still reads
  const after = (await open([])).state
  expect(after.members['ci']).toBeDefined()
  expect(after.tiers).toEqual(before.tiers)
  expect((await (await open([key])).scan()).entries.map((entry): string => entry.payload.name)).toEqual(['openai'])

  // and retrying completes the removal
  expect(await admin.removeMember('ci')).toEqual(['openai'])
  expect((await (await open([key])).scan()).entries).toEqual([])
})

it('keeps other members reading after a removal rotates tiers they share', async () => {
  // given two members on a tier that includes another
  await admin.include('trusted', 'member')
  await put('openai', 'member')
  await put('stripe', 'trusted')
  const staying = await addMachine('ci', ['trusted'])
  await addMachine('bot', ['trusted'])

  // when one leaves
  expect(await admin.removeMember('bot')).toEqual(['openai', 'stripe'])

  // then the other still reads both tiers at their new generations
  const vault = await open([staying])
  expect(vault.state.tiers['member']?.gen).toBe(5)
  expect((await vault.scan()).entries.map((entry): string => entry.payload.name).sort()).toEqual(['openai', 'stripe'])
})
