import { describe, expect, test } from 'bun:test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

import {
  type EntryPayload,
  generateSecretKey,
  openEntry,
  openWrap,
  parseEntryName,
  publicKeyOf,
  recipientOf,
  RevisionLedger,
  sealEntry,
  sealWrap,
  signerOf,
  verifyEnvelope,
  type VaultState,
  wrapPath,
} from './portable'

const ENTRY = join(import.meta.dir, 'portable.ts')

/** Every module the portable entry reaches, following relative imports; bare specifiers are listed, not followed. */
async function importGraph(
  entry: string,
): Promise<{ readonly files: ReadonlySet<string>; readonly bare: Set<string> }> {
  const transpiler = new Bun.Transpiler({ loader: 'ts' })
  const files = new Set<string>()
  const bare = new Set<string>()
  const visit = async (file: string): Promise<void> => {
    if (files.has(file)) return
    files.add(file)
    for (const { path, kind } of transpiler.scanImports(await Bun.file(file).text())) {
      if (kind === 'dynamic-import' || kind === 'require-call') bare.add(`${kind}:${path}`)
      if (path.startsWith('.')) await visit(resolve(dirname(file), path.endsWith('.json') ? path : `${path}.ts`))
      else bare.add(path)
    }
  }
  await visit(entry)
  return { files, bare }
}

describe('the portable core', () => {
  test('reaches no Node, Bun or file-system module, so a browser bundle can carry it', async () => {
    const { bare } = await importGraph(ENTRY)
    const runtime = [...bare].filter(
      (path) => path.startsWith('node:') || path.startsWith('bun:') || path.includes(':'),
    )
    expect(runtime).toEqual([])
    expect([...bare].sort()).toEqual(
      [
        '@noble/curves/ed25519.js',
        '@noble/hashes/sha2.js',
        '@noble/hashes/utils.js',
        '@scure/base',
        'age-encryption',
        'zod',
      ].sort(),
    )
  })

  test('calls no Bun global, which a browser does not have', async () => {
    const { files } = await importGraph(ENTRY)
    const users = await Promise.all(
      [...files].map(async (file) => ((await Bun.file(file).text()).includes('Bun.') ? [file] : [])),
    )
    expect(users.flat()).toEqual([])
  })

  test('the published typevault/core export resolves and bundles for the browser', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tv-export-'))
    const entry = join(dir, 'entry.ts')
    await Bun.write(entry, "export { openWrap, sealEntry, verifyEnvelope } from 'typevault/core'\n")
    await Bun.write(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'consumer', dependencies: { typevault: `file:${resolve(import.meta.dir, '../..')}` } }),
    )
    const linked = join(dir, 'node_modules')
    await Bun.$`mkdir -p ${linked} && ln -s ${resolve(import.meta.dir, '../..')} ${join(linked, 'typevault')}`.quiet()
    const result = await Bun.build({ entrypoints: [entry], target: 'browser' })
    expect(result.logs.filter((log) => log.level === 'error')).toEqual([])
    expect(result.success).toBe(true)
  })

  test('bundles for the browser target', async () => {
    const result = await Bun.build({ entrypoints: [ENTRY], target: 'browser' })
    expect(result.success).toBe(true)
  })
})

const NOW = '2026-11-24T00:00:00.000Z'
const payload: EntryPayload = {
  v: 1,
  name: parseEntryName('soniox'),
  fields: { $default: { type: 'secret', value: 'sk-test' } },
  tags: [],
  created: NOW,
  rotated: NOW,
}

async function stateWithTier(): Promise<{
  readonly state: VaultState
  readonly tierKey: Awaited<ReturnType<typeof generateSecretKey>>
}> {
  const owner = await publicKeyOf(await generateSecretKey({ kind: 'owner' }))
  const tierKey = await generateSecretKey({ kind: 'tier', tier: 'mesh', gen: 1 })
  const state: VaultState = {
    owner,
    origin: 'origin',
    handovers: [],
    seqs: { tiers: 1, members: 1, signers: 1, ceilings: 1 },
    tiers: { mesh: { includes: [], gen: 1, ...(await publicKeyOf(tierKey)) } },
    members: {},
    signers: {},
    ceilings: {},
  }
  return { state, tierKey }
}

describe('tier-key wraps opened by a non-extractable device key', () => {
  test('a wrap sealed to a WebCrypto X25519 key opens only with that key and only as the expected tier key', async () => {
    const device = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])
    if (!('privateKey' in device)) throw new Error('expected a key pair')
    const tierKey = await generateSecretKey({ kind: 'tier', tier: 'mesh', gen: 1 })
    const expected = await publicKeyOf(tierKey)
    const sealed = await sealWrap(tierKey, [await recipientOf(device.privateKey)])

    expect(await openWrap(sealed, [device.privateKey], expected)).toEqual(tierKey)

    const planted = await generateSecretKey({ kind: 'tier', tier: 'mesh', gen: 1 })
    expect(await openWrap(sealed, [device.privateKey], await publicKeyOf(planted))).toBeUndefined()

    const other = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])
    if (!('privateKey' in other)) throw new Error('expected a key pair')
    expect(await openWrap(sealed, [other.privateKey], expected)).toBeUndefined()
  })

  test('wrap paths use forward slashes on every platform', () => {
    expect(wrapPath('mesh', 2, { kind: 'member', name: 'phone' })).toBe('tiers/mesh/2/members/phone.age')
  })
})

describe('entries without a vault directory', () => {
  test('seal, verify and open an entry against in-memory state', async () => {
    const { state, tierKey } = await stateWithTier()
    const envelope = await sealEntry(
      { id: 'mesh.0123456789abcdef0123456789abcdef', tier: 'mesh', rev: 1, at: NOW, payload },
      state,
      signerOf(tierKey),
    )
    expect(verifyEnvelope(envelope, state)).toBeUndefined()
    const noGrants = () => false
    expect(
      await openEntry(envelope, { unlock: async (tier) => (tier === 'mesh' ? tierKey : undefined) }, noGrants),
    ).toEqual(payload)

    const forged = { ...envelope, rev: 2 }
    expect(verifyEnvelope(forged, state)).toBe('bad signature')
  })
})

describe("verification without the reader's clock", () => {
  test('ignoreClock checks the signature of an envelope written ahead of this clock, and still refuses a forged one', async () => {
    const { state, tierKey } = await stateWithTier()
    const ahead = new Date(Date.now() + 60 * 60_000).toISOString()
    const envelope = await sealEntry(
      { id: 'mesh.0123456789abcdef0123456789abcdef', tier: 'mesh', rev: 1, at: ahead, payload },
      state,
      signerOf(tierKey),
    )
    expect(verifyEnvelope(envelope, state)).toBe('timestamp is in the future')
    expect(verifyEnvelope(envelope, state, { ignoreClock: true })).toBeUndefined()
    expect(verifyEnvelope({ ...envelope, rev: 9 }, state, { ignoreClock: true })).toBe('bad signature')
  })
})

describe('revision ledger', () => {
  test('refuses a revision older than one already seen, and anything after a tombstone', () => {
    const ledger = new RevisionLedger({ a: 2 })
    expect(ledger.accept('a', 1)).toBe(false)
    expect(ledger.accept('a', 3)).toBe(true)
    ledger.tombstone('b')
    expect(ledger.allows('b', 100)).toBe(false)
    expect(ledger.snapshot()).toEqual({ a: 3, b: Number.MAX_SAFE_INTEGER })
  })
})
