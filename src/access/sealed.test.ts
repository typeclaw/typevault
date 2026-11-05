import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { generateX25519Identity, identityToRecipient } from 'age-encryption'

import { seal } from '../core/crypto'
import { toBase64Url, utf8 } from '../core/encoding'
import { readSealedGrant } from './sealed'

let root: string
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'tv-sealed-'))
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

it.each(['@', 'missing', 'directory'])('maps unreadable sealed grant file %s to invalid', async (input) => {
  const path = input === '@' ? '' : input === 'directory' ? root : join(root, 'missing')
  await expect(readSealedGrant(`@${path}`)).rejects.toMatchObject({
    code: 'invalid',
    message: expect.stringContaining(path),
  })
})

it.each(['tvg1:abc.def', 'tvg1:!.!', 'tvg1:', 'tvg1:YWJj.ZGVm', 'tvg1:a.b.c'])(
  'maps malformed sealed grant %s to invalid',
  async (token) => {
    await expect(readSealedGrant(token)).rejects.toMatchObject({ code: 'invalid' })
  },
)

it.each(['not JSON', '{}'])('maps decrypted malformed payload %s to invalid', async (text) => {
  const identity = await generateX25519Identity()
  const ciphertext = await seal([await identityToRecipient(identity)], utf8(text))
  const token = `tvg1:${toBase64Url(utf8(identity))}.${toBase64Url(ciphertext)}`
  const path = join(root, 'grant')
  writeFileSync(path, token)

  await expect(readSealedGrant(`@${path}`)).rejects.toMatchObject({ code: 'invalid' })
})
