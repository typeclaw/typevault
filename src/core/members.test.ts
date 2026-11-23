import { afterEach, beforeEach, expect, it, spyOn } from 'bun:test'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from './admin'
import { type SecretKey, unseal } from './crypto'
import { fromBase64 } from './encoding'
import { type Envelope, signerOf } from './entries'
import { createIdentity } from './identity'
import { founderOf, initGlobalVault } from './init'
import { wrapPath } from './keyring'
import { globalLayout } from './layout'
import { parseEntryName } from './naming'
import { membersDoc } from './state'
import { Txn } from './txn'
import { Vault } from './vault'

const envIn = (dir: string) => ({ TYPEVAULT_DIR: join(dir, 'vault'), XDG_CONFIG_HOME: dir })

let root: string
let owner: SecretKey
let alice: SecretKey
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
  alice = founder.key
  admin = new Admin(await open([alice]))
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
  const { affected } = await admin.removeMember('ci')

  // then its key opens nothing, and only what it reached needs rotating at the source
  expect(affected).toEqual(['openai'])
  expect((await (await open([key])).scan()).entries).toEqual([])
  expect(Object.keys((await open([])).state.members)).toEqual(['alice'])
})

it('refuses to remove an owner', async () => {
  await expect(admin.removeMember('alice')).rejects.toMatchObject({
    code: 'invalid',
    message: expect.stringContaining('add another owner first'),
  })
})

it('refuses to rotate the owner past an entry no held key can open', async () => {
  // given a second owner, and an entry whose tier the owner key no longer opens
  const bob = await createIdentity('bob', 'machine')
  await admin.addMember('bob', { ...founderOf(bob.identity).member, owner: true, tiers: [] })
  const entry = await put('openai', 'member')
  const before = (await open([])).state
  rmSync(join(globalLayout(envIn(root)).vault, wrapPath('member', before.tiers['member']?.gen ?? 0, { kind: 'owner' })))

  // when Bob is removed, which rotates the owner key
  const removing = admin.removeMember('bob')

  // then the rotation names the entry it can't re-seal and changes nothing
  await expect(removing).rejects.toMatchObject({ code: 'tampered', message: expect.stringContaining(entry.id) })
  const after = (await open([])).state
  expect(after.owner).toEqual(before.owner)
  expect(after.members['bob']).toBeDefined()
})

it('revokes a co-owner even if they saved the shared owner key and a tier key', async () => {
  // given two owners and secrets in independent tiers
  const bob = await createIdentity('bob', 'machine')
  await admin.addMember('bob', { ...founderOf(bob.identity).member, owner: true, tiers: [] })
  await put('openai', 'member')
  await put('stripe', 'trusted')
  const oldTier = await (await open([bob.key])).keyring.unlock('member')
  if (oldTier === undefined) throw new Error('expected a tier key')

  // when Bob removes Alice, and writes another entry under the new owner
  expect((await new Admin(await open([bob.key])).removeMember('alice')).affected).toEqual(['openai', 'stripe'])
  const remaining = await open([bob.key])
  const next = remaining.keyring.owner
  if (next === undefined) throw new Error('expected the new owner key')
  await remaining.put(
    { name: parseEntryName('later'), fields: { key: { type: 'secret', value: 'new' } }, tier: 'member' },
    signerOf(next),
  )

  // then all three ciphertexts are readable by Bob, but none by the saved keys
  const { entries, problems } = await remaining.scan()
  expect(problems).toEqual([])
  expect(
    entries.map(({ payload }): [string, boolean] => [payload.name, payload.needsRotation === true]).sort(),
  ).toEqual([
    ['later', false],
    ['openai', true],
    ['stripe', true],
  ])
  for (const { envelope } of entries) {
    await expect(unseal([owner.identity, oldTier.identity], fromBase64(envelope.payload))).rejects.toMatchObject({
      code: 'denied',
    })
  }
  const revoked = await open([alice])
  expect(revoked.keyring.owner).toBeUndefined()
  expect((await revoked.scan()).entries).toEqual([])
  expect(existsSync(join(remaining.layout.membersDir, 'alice.key'))).toBe(false)
  expect(existsSync(join(remaining.layout.ownerWrapsDir, 'alice.age'))).toBe(false)
  await expect(open([owner])).rejects.toMatchObject({ code: 'denied' })
  await expect(admin.addTier('stale')).rejects.toMatchObject({ code: 'locked' })
})

it('refuses to list one key under a second name', async () => {
  const { identity } = await createIdentity('ci', 'machine')
  await admin.addMember('ci', { ...founderOf(identity).member, owner: false, tiers: ['member'] })

  await expect(
    admin.addMember('ci-copy', { ...founderOf(identity).member, owner: true, tiers: [] }),
  ).rejects.toMatchObject({ code: 'conflict' })
})

it.each([
  ['an owner', true, []],
  ['a tier member', false, ['member']],
] as const)("removes %s listing a removed owner's key under another name", async (_, aliasOwner, aliasTiers) => {
  // given Bob as a second owner, and Alice's key also listed under another name
  const bob = await createIdentity('bob', 'machine')
  await admin.addMember('bob', { ...founderOf(bob.identity).member, owner: true, tiers: [] })
  const before = (await open([])).state
  const listed = before.members['alice']
  if (listed === undefined) throw new Error('expected alice')
  const alias = { ...listed, owner: aliasOwner, tiers: [...aliasTiers] }
  const layout = globalLayout(envIn(root))
  writeFileSync(
    layout.membersFile,
    membersDoc({ ...before.members, 'alice-alias': alias }, owner, before.seqs.members + 1),
  )

  // when Bob removes Alice
  await new Admin(await open([bob.key])).removeMember('alice')

  // then the alias is gone too, so no new owner or tier key is wrapped to Alice's key
  const after = (await open([])).state
  expect(Object.keys(after.members)).toEqual(['bob'])
  expect(existsSync(join(layout.ownerWrapsDir, 'alice-alias.age'))).toBe(false)
  const gen = after.tiers['member']?.gen ?? 0
  expect(existsSync(join(layout.vault, wrapPath('member', gen, { kind: 'member', name: 'alice-alias' })))).toBe(false)
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
  expect((await admin.removeMember('ci')).affected).toEqual(['openai'])
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
  expect((await admin.removeMember('bot')).affected).toEqual(['openai', 'stripe'])

  // then the other still reads both tiers at their new generations
  const vault = await open([staying])
  expect(vault.state.tiers['member']?.gen).toBe(5)
  expect((await vault.scan()).entries.map((entry): string => entry.payload.name).sort()).toEqual(['openai', 'stripe'])
})
