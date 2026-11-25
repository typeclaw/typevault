import { describe, expect, test } from 'bun:test'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  type EntryPayload,
  generateSecretKey,
  openWrap,
  parseEntryName,
  publicKeyOf,
  RevisionLedger,
  seal,
  sealEntry,
  signCiphertext,
  signerOf,
  type VaultState,
  verifyEnvelope,
} from './portable'
import { RevisionMarks } from './revisions'

const NOW = '2026-11-24T00:00:00.000Z'
const payload: EntryPayload = {
  v: 1,
  name: parseEntryName('soniox'),
  fields: { $default: { type: 'secret', value: 'sk-test' } },
  tags: [],
  created: NOW,
  rotated: NOW,
}

async function stateWithTier() {
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

describe('openWrap', () => {
  test('a wrap whose plaintext is not UTF-8 or not a key yields undefined, so the next wrap can be tried', async () => {
    const identity = (await generateSecretKey({ kind: 'member', name: 'phone' })).identity
    const recipient = (await publicKeyOf(await generateSecretKey({ kind: 'member', name: 'phone' }))).recipient
    const own = await import('./crypto').then((crypto) => crypto.recipientOf(identity))
    const expected = { recipient, signPublic: 'x' }
    for (const plaintext of [new Uint8Array([0xff, 0xfe, 0xfd]), new TextEncoder().encode('tvk1:!!!not-base64!!!')]) {
      expect(await openWrap(await seal([own], plaintext), [identity], expected)).toBeUndefined()
    }
  })
})

describe('verifyEnvelope', () => {
  test('a signer id that names an inherited property is refused, not thrown', async () => {
    const { state, tierKey } = await stateWithTier()
    const envelope = await sealEntry(
      { id: 'mesh.0123456789abcdef0123456789abcdef', tier: 'mesh', rev: 1, at: NOW, payload },
      state,
      signerOf(tierKey),
    )
    for (const id of ['constructor', '__proto__', 'toString'])
      expect(verifyEnvelope({ ...envelope, signer: { kind: 'signer', id } }, state)).toBe(
        'signer is not allowed to write this tier',
      )
  })
})

describe('signCiphertext', () => {
  test('refuses draft metadata the receiving vault would reject, instead of signing it', async () => {
    const { state, tierKey } = await stateWithTier()
    const ciphertext = new Uint8Array([1, 2, 3])
    const good = { id: 'mesh.0123456789abcdef0123456789abcdef', tier: 'mesh', rev: 1, at: NOW }
    for (const draft of [
      { ...good, id: '6f1c2a3e-uuid' },
      { ...good, id: 'other.0123456789abcdef0123456789abcdef' },
      { ...good, rev: 0 },
      { ...good, at: 'yesterday' },
    ])
      expect(() => signCiphertext(draft, ciphertext, state, signerOf(tierKey))).toThrow(
        expect.objectContaining({ code: 'invalid' }),
      )
  })
})

describe('RevisionLedger', () => {
  test('a tombstone refuses every revision, the highest valid one included', () => {
    const ledger = new RevisionLedger()
    ledger.tombstone('gone')
    expect(ledger.allows('gone', Number.MAX_SAFE_INTEGER)).toBe(false)
    expect(ledger.accept('gone', Number.MAX_SAFE_INTEGER)).toBe(false)
  })

  test('a save that fails keeps the marks dirty, so the next save writes them', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tv-marks-'))
    writeFileSync(join(dir, 'blocker'), '')
    const marks = new RevisionMarks(join(dir, 'blocker', 'marks.json'))
    marks.accept('a', 2)
    expect(() => marks.save()).toThrow()
    expect(marks.dirty).toBe(true)
  })
})
