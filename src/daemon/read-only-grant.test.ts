import { expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { z } from 'zod'

import { createAdmin } from '../admin'
import { Admin } from '../core/admin'
import { sha256Hex } from '../core/crypto'
import { utf8 } from '../core/encoding'
import { signerOf } from '../core/entries'
import { createIdentity } from '../core/identity'
import { founderOf, initGlobalVault } from '../core/init'
import { globalLayout } from '../core/layout'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { startDaemon } from './daemon'
import { LiveAccess } from './live-access'

it('keeps an SDK-issued read-only grant scoped and denies mutations and delegation after restart', async () => {
  // Keep Unix socket paths short on all test hosts.
  const shortTmp = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
  mkdirSync(shortTmp, { recursive: true })
  const root = mkdtempSync(join(shortTmp, 'tvr-'))
  let daemon: Awaited<ReturnType<typeof startDaemon>> | undefined
  try {
    const dir = join(root, 'vault')
    const env = { TYPEVAULT_DIR: dir, XDG_CONFIG_HOME: root }
    const layout = globalLayout(env)
    const { identity } = await createIdentity('owner', 'machine')
    const { owner } = await initGlobalVault(founderOf(identity), env)
    const vault = await Vault.open(layout, [owner], {})
    await new Admin(vault).addTier('member')
    const name = parseEntryName('fixture/allowed')
    const hidden = parseEntryName('fixture/hidden')
    for (const entry of [name, hidden]) {
      await vault.put(
        { name: entry, tier: 'member', fields: { key: { type: 'secret', value: 'dummy' } } },
        signerOf(owner),
      )
    }
    const start = () => startDaemon({ layout, env, keys: [owner] })
    daemon = await start()
    const admin = createAdmin({ dir, env })
    const request = { tiers: ['member'], only: [name], label: 'fixture:reader', readOnly: true }
    await expect(admin.grant({ ...request, sealed: true })).rejects.toMatchObject({ code: 'invalid' })
    const token = await admin.grant(request)
    expect(await admin.list()).toContainEqual(expect.objectContaining({ label: request.label, readOnly: true }))
    const [, , secret] = token.split('.')
    if (secret === undefined) throw new Error('missing token secret segment')
    // The previous daemon only compares the legacy hash of this single token segment.
    expect(readFileSync(layout.grantsFile, 'utf8')).not.toContain(sha256Hex(utf8(secret)))
    await daemon.stop()
    // A pre-feature daemon preserves known fields but strips readOnly before saving.
    const saved = z
      .array(z.object({ readOnly: z.literal(true).optional() }).passthrough())
      .parse(JSON.parse(readFileSync(layout.grantsFile, 'utf8')))
    writeFileSync(layout.grantsFile, JSON.stringify(saved.map(({ readOnly: _discarded, ...record }) => record)))
    daemon = await start()
    expect(await admin.list()).toContainEqual(expect.objectContaining({ label: request.label, readOnly: true }))

    const reader = new LiveAccess(layout.agentSocket, token)
    expect((await reader.list()).map((entry) => entry.name)).toEqual([name])
    expect((await reader.get(name)).fields['key']).toEqual({ type: 'secret', value: 'dummy' })
    await expect(reader.get(hidden)).rejects.toMatchObject({ code: 'not_found' })
    for (const [route, body] of [
      ['/v1/set', { name, fields: { key: { type: 'secret', value: 'replacement' } } }],
      ['/v1/remove', { name }],
      ['/v1/move', { from: name, to: hidden }],
      ['/v1/import/stage', { chunk: 'W10=' }],
      ['/v1/import', { upload: 'not-staged', tier: 'member' }],
      ['/v1/derive', {}],
      ['/v1/attach', { vault: dir }],
      ['/v1/request', { name, reason: 'fixture' }],
    ] as const) {
      await expect(reader.call(route, body, z.json())).rejects.toMatchObject({
        code: 'denied',
        message: 'this grant is read-only',
      })
    }
    expect(await admin.revoke({ label: request.label })).toHaveLength(1)
    await expect(reader.list()).rejects.toMatchObject({ code: 'denied' })
  } finally {
    try {
      await daemon?.stop()
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }
})
