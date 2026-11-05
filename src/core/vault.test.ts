import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Admin } from './admin'
import { decodeSecretKey, generateSigningKey, seal, type SecretKey, unseal } from './crypto'
import { fromBase64, fromUtf8, utf8 } from './encoding'
import { signerOf } from './entries'
import { TypeVaultError } from './errors'
import { createIdentity } from './identity'
import { type Founder, founderOf, initGlobalVault } from './init'
import { wrapPath } from './keyring'
import { globalLayout } from './layout'
import { parseEntryName } from './naming'
import { Vault } from './vault'

const envIn = (dir: string) => ({ TYPEVAULT_DIR: join(dir, 'vault'), XDG_CONFIG_HOME: dir })

const machineFounder = async (): Promise<Founder> => founderOf((await createIdentity('owner', 'machine')).identity)

let root: string
let owner: SecretKey
let admin: Admin

const env = {}
const open = (keys: readonly SecretKey[]): Promise<Vault> => Vault.open(globalLayout(envIn(root)), keys, env)
const keyOf = async (tier: string): Promise<SecretKey> => {
  const key = await (await open([owner])).keyring.unlock(tier)
  if (key === undefined) throw new Error(`no key for ${tier}`)
  return key
}
const stripe = {
  name: parseEntryName('stripe'),

  fields: { key: { type: 'secret' as const, value: 'sk_test_123' } },
  tier: 'member',
} as const

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'typevault-'))
  owner = (await initGlobalVault(await machineFounder(), envIn(root))).owner
  admin = new Admin(await open([owner]))
  await admin.addTier('guest')
  await admin.addTier('member')
  await admin.addTier('trusted')
  await admin.include('member', 'guest')
  await admin.include('trusted', 'member')
})

afterEach(() => rmSync(root, { recursive: true, force: true }))

describe('tier access', () => {
  it('lets a tier key read entries of the tiers it includes, transitively', async () => {
    await (await open([owner])).put(stripe, signerOf(owner))
    const trusted = await open([await keyOf('trusted')])
    expect((await trusted.find(stripe.name))?.payload.fields).toEqual({
      key: { type: 'secret' as const, value: 'sk_test_123' },
    })
  })

  it('hides entries of tiers a key does not reach', async () => {
    await (await open([owner])).put(stripe, signerOf(owner))
    const guest = await open([await keyOf('guest')])
    expect(await guest.find(stripe.name)).toBeUndefined()
  })

  it('refuses a write signed by a tier key that does not reach the target tier', async () => {
    const guestKey = await keyOf('guest')
    const guest = await open([guestKey])
    await expect(guest.put(stripe, signerOf(guestKey))).rejects.toThrow(TypeVaultError)
  })

  it('accepts a write signed by an including tier key', async () => {
    const trustedKey = await keyOf('trusted')
    await (await open([trustedKey])).put(stripe, signerOf(trustedKey))
    expect((await (await open([await keyOf('member')])).find(stripe.name))?.envelope.rev).toBe(1)
  })
})

describe('integrity', () => {
  it('reports a tampered entry instead of returning it', async () => {
    const vault = await open([owner])
    const { envelope } = await vault.put(stripe, signerOf(owner))
    const file = join(root, 'vault', 'entries', `${envelope.id}.json`)
    writeFileSync(file, readFileSync(file, 'utf8').replace('"rev": 1', '"rev": 7'))
    const scan = await vault.scan()
    expect(scan.entries).toHaveLength(0)
    expect(scan.problems).toEqual([{ file: `${envelope.id}.json`, reason: 'bad signature' }])
  })

  it('contains a validly signed but undecryptable entry instead of failing every scan', async () => {
    const vault = await open([owner])
    await vault.put(stripe, signerOf(owner))
    await vault.putCiphertext(parseEntryName('junk'), 'member', new Uint8Array([1, 2, 3]), signerOf(owner))
    const scan = await vault.scan()
    expect(scan.entries.map((entry): string => entry.payload.name)).toEqual(['stripe'])
    expect(scan.problems).toHaveLength(1)
  })

  it('stores fields the entry type does not list, keeping their names as written', async () => {
    const vault = await open([owner])
    await vault.put(
      {
        ...stripe,
        fields: {
          key: { type: 'secret' as const, value: 'x' },
          'Webhook Secret': { type: 'secret' as const, value: 'whsec' },
        },
      },
      signerOf(owner),
    )
    expect((await vault.find(stripe.name))?.payload.fields).toEqual({
      key: { type: 'secret' as const, value: 'x' },
      'Webhook Secret': { type: 'secret' as const, value: 'whsec' },
    })
  })

  it.each(['', 'a=b', ' padded', 'line\nbreak', 'x'.repeat(65)])(
    'refuses to store the field name %p',
    async (field) => {
      const vault = await open([owner])
      await expect(
        vault.put(
          {
            ...stripe,
            fields: { key: { type: 'secret' as const, value: 'x' }, [field]: { type: 'secret' as const, value: 'y' } },
          },
          signerOf(owner),
        ),
      ).rejects.toMatchObject({
        code: 'invalid',
      })
    },
  )

  it('never lets a lower tier shadow a name held by a higher tier', async () => {
    const vault = await open([owner])
    await vault.put({ ...stripe, tier: 'trusted' }, signerOf(owner))
    const guestKey = await keyOf('guest')
    const guest = await open([guestKey])
    await guest.put(
      { ...stripe, tier: 'guest', fields: { key: { type: 'secret' as const, value: 'ATTACKER' } } },
      signerOf(guestKey),
    )
    await expect((await open([await keyOf('trusted')])).find(stripe.name)).resolves.toMatchObject({
      payload: { fields: { key: { type: 'secret' as const, value: 'sk_test_123' } } },
    })
  })

  it('reports an entry swapped back to an older signed revision', async () => {
    const vault = await open([owner])
    const first = await vault.put(stripe, signerOf(owner))
    await vault.scan()
    await vault.put({ ...stripe, fields: { key: { type: 'secret' as const, value: 'sk_test_456' } } }, signerOf(owner))
    await vault.scan()
    const file = join(root, 'vault', 'entries', `${first.envelope.id}.json`)
    writeFileSync(file, JSON.stringify(first.envelope))
    const scan = await vault.scan()
    expect(scan.entries).toHaveLength(0)
    expect(scan.problems[0]?.reason).toContain('replaced or deleted')
  })

  it('settles a name held by unrelated tiers by removing one copy', async () => {
    const vault = await open([owner])
    await admin.addTier('ci')
    await vault.put(stripe, signerOf(owner))
    const ciKey = await keyOf('ci')
    await (
      await open([ciKey])
    ).put({ ...stripe, tier: 'ci', fields: { key: { type: 'secret' as const, value: 'from-ci' } } }, signerOf(ciKey))
    await expect(vault.find(stripe.name)).rejects.toMatchObject({ code: 'conflict' })
    await vault.remove(stripe.name, 'ci')
    expect((await vault.find(stripe.name))?.payload.fields).toEqual({
      key: { type: 'secret' as const, value: 'sk_test_123' },
    })
  })

  it('refuses a deleted entry restored from history', async () => {
    const vault = await open([owner])
    const old = await vault.put(stripe, signerOf(owner))
    await vault.remove(stripe.name)
    await vault.put({ ...stripe, fields: { key: { type: 'secret' as const, value: 'sk_test_new' } } }, signerOf(owner))
    writeFileSync(join(root, 'vault', 'entries', `${old.envelope.id}.json`), JSON.stringify(old.envelope))
    expect((await vault.find(stripe.name))?.payload.fields).toEqual({
      key: { type: 'secret' as const, value: 'sk_test_new' },
    })
  })

  it('ignores a planted, malformed key wrap instead of failing every scan', async () => {
    const vault = await open([owner])
    await vault.put(stripe, signerOf(owner))
    const gen = vault.state.tiers['member']?.gen ?? 0
    const wrap = join(root, 'vault', 'tiers', 'member', String(gen), 'owner.age')
    writeFileSync(wrap, await seal([vault.state.owner.recipient], utf8('tvk1:bm90IGpzb24')))
    const viaTrusted = await open([await keyOf('trusted')])
    expect((await viaTrusted.find(stripe.name))?.payload.fields).toEqual({
      key: { type: 'secret' as const, value: 'sk_test_123' },
    })
    await expect((await open([owner])).scan()).resolves.toBeDefined()
  })

  it('refuses a committed symlink inside the vault tree', async () => {
    const vault = await open([owner])
    const tiers = join(root, 'vault', 'tiers')
    renameSync(tiers, join(root, 'tiers-real'))
    symlinkSync(join(root, 'tiers-real'), tiers)
    await expect(admin.addTier('extra')).rejects.toMatchObject({ code: 'tampered' })
    expect(vault).toBeDefined()
  })

  it('rejects a manifest rolled back to an older signed copy', async () => {
    const file = join(root, 'vault', 'signers.json')
    const before = readFileSync(file, 'utf8')
    await admin.setSigner('ci', generateSigningKey().signPublic, ['member'])
    await admin.removeSigner('ci')
    await open([owner])
    writeFileSync(file, before)
    await expect(open([owner])).rejects.toMatchObject({ code: 'tampered' })
  })

  it('validates signer ids, public keys and tiers', async () => {
    const { signPublic } = generateSigningKey()
    await expect(admin.setSigner('bad id', signPublic, ['member'])).rejects.toMatchObject({ code: 'invalid' })
    await expect(admin.setSigner('ci', 'garbage', ['member'])).rejects.toMatchObject({ code: 'invalid' })
    await expect(admin.setSigner('ci', signPublic, ['missing'])).rejects.toMatchObject({ code: 'not_found' })
    await expect(admin.setSigner('ci', signPublic, [])).rejects.toMatchObject({ code: 'invalid' })
    await expect(admin.setSigner('ci', signPublic, ['member'])).resolves.toBeUndefined()
  })

  it('errors without bumping manifests when signer or ceiling ids are missing', async () => {
    const before = (await open([owner])).state.seqs
    await expect(admin.removeSigner('missing')).rejects.toMatchObject({ code: 'not_found' })
    await expect(admin.removeCeiling('missing')).rejects.toMatchObject({ code: 'not_found' })
    expect((await open([owner])).state.seqs).toEqual(before)
  })

  it('rejects a vault whose owner key changed after it was first trusted', async () => {
    const file = join(root, 'vault', 'owner.json')
    const doc = JSON.parse(readFileSync(file, 'utf8'))
    writeFileSync(file, JSON.stringify({ ...doc, signPublic: 'AAAA' }))
    await expect(open([owner])).rejects.toMatchObject({ code: 'tampered' })
  })

  it('rejects a stale revision on compare-and-swap', async () => {
    const vault = await open([owner])
    await vault.put(stripe, signerOf(owner))
    await expect(vault.put(stripe, signerOf(owner), { ifRev: 0 })).rejects.toMatchObject({ code: 'conflict' })
    expect((await vault.put(stripe, signerOf(owner), { ifRev: 1 })).envelope.rev).toBe(2)
  })

  it('moves an entry to another tier under a new id, leaving no copy behind', async () => {
    const vault = await open([owner])
    const before = await vault.put(stripe, signerOf(owner))
    const after = await vault.put({ ...stripe, tier: 'trusted' }, signerOf(owner))
    const { entries, problems } = await vault.scan()
    expect(after.envelope.id).not.toBe(before.envelope.id)
    expect(entries.map((entry) => entry.envelope.tier)).toEqual(['trusted'])
    expect(problems).toEqual([])
  })

  it('serializes concurrent writes from one process', async () => {
    const vault = await open([owner])
    const names = ['a', 'b', 'c', 'd'].map((name) => ({ ...stripe, name: parseEntryName(name) }))
    await Promise.all(names.map((input) => vault.put(input, signerOf(owner))))
    expect((await vault.scan()).entries.map((entry): string => entry.payload.name).sort()).toEqual(['a', 'b', 'c', 'd'])
  })
})

describe('rotation', () => {
  it('locks out the old key, keeps includers working and flags reachable entries', async () => {
    const vault = await open([owner])
    await vault.put(stripe, signerOf(owner))
    const guest = { ...stripe, name: parseEntryName('guest-secret'), tier: 'guest' }
    const unrelated = { ...stripe, name: parseEntryName('unrelated'), tier: 'trusted' }
    await vault.put(guest, signerOf(owner))
    await vault.put(unrelated, signerOf(owner))
    const trustedGen = vault.state.tiers['trusted']?.gen
    const oldMember = await keyOf('member')
    expect(await admin.rotate('member')).toEqual(['guest-secret', 'stripe'])
    expect(await (await open([oldMember])).find(stripe.name)).toBeUndefined()
    const viaTrusted = await open([await keyOf('trusted')])
    expect((await viaTrusted.find(stripe.name))?.payload.needsRotation).toBe(true)
    expect((await viaTrusted.find(guest.name))?.payload.needsRotation).toBe(true)
    expect((await viaTrusted.find(unrelated.name))?.payload.needsRotation).toBeUndefined()
    expect(viaTrusted.state.tiers['trusted']?.gen).toBe(trustedGen)
  })

  it.each(['member', 'guest'])('keeps historical trusted wraps from opening re-set %s entries', async (tier) => {
    const vault = await open([owner])
    const oldTrusted = await keyOf('trusted')
    let historicalKey = oldTrusted
    for (const included of tier === 'member' ? ['member'] : ['member', 'guest']) {
      const wrap = wrapPath(included, vault.state.tiers[included]?.gen ?? 0, historicalKey.role)
      historicalKey = decodeSecretKey(
        fromUtf8(await unseal([historicalKey.identity], readFileSync(join(vault.layout.vault, wrap)))),
      )
    }
    const entry = { ...stripe, tier }
    const before = await vault.put(entry, signerOf(owner))
    await expect(unseal([historicalKey.identity], fromBase64(before.envelope.payload))).resolves.toBeDefined()

    await admin.rotate('trusted')
    const fields = { key: { type: 'secret' as const, value: 'dummy-rotated-value' } }
    const current = await vault.put({ ...entry, fields }, signerOf(owner))

    await expect(unseal([historicalKey.identity], fromBase64(current.envelope.payload))).rejects.toMatchObject({
      code: 'denied',
    })
    const viaTrusted = await open([await keyOf('trusted')])
    expect((await viaTrusted.find(entry.name))?.payload.fields).toEqual(fields)
    expect(current.payload.needsRotation).toBeUndefined()
  })

  it('clears the rotation flag when the value is re-set', async () => {
    const vault = await open([owner])
    await vault.put(stripe, signerOf(owner))
    await admin.rotate('member')
    const reset = await vault.put(
      { ...stripe, fields: { key: { type: 'secret' as const, value: 'sk_test_456' } } },
      signerOf(owner),
    )
    expect(reset.payload.needsRotation).toBeUndefined()
  })

  it('stops an excluded tier from reaching the formerly included one', async () => {
    await (await open([owner])).put(stripe, signerOf(owner))
    const trustedKey = await keyOf('trusted')
    await admin.exclude('trusted', 'member')
    expect(await (await open([trustedKey])).find(stripe.name)).toBeUndefined()
  })

  it('drops the include and rotates in one transaction', async () => {
    // given
    const before = (await open([owner])).state

    // when
    await admin.exclude('trusted', 'member')

    // then a crash can't land the dropped include without the rotation: both share one tiers.json change
    const after = (await open([owner])).state
    expect(after.seqs.tiers).toBe(before.seqs.tiers + 1)
    expect(after.tiers['trusted']?.includes).not.toContain('member')
    expect(after.tiers['member']?.gen).toBe((before.tiers['member']?.gen ?? 0) + 1)
  })

  it('refuses an include that would form a cycle', async () => {
    await expect(admin.include('guest', 'trusted')).rejects.toMatchObject({ code: 'invalid' })
  })

  it('leaves no staged transaction behind', async () => {
    await admin.rotate('trusted')
    expect(readdirSync(globalLayout(envIn(root)).txnDir)).toEqual([])
  })
})
