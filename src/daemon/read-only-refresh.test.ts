import { expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { createAdmin } from '../admin'
import { Admin } from '../core/admin'
import { signerOf } from '../core/entries'
import { createIdentity } from '../core/identity'
import { founderOf, initGlobalVault } from '../core/init'
import { globalLayout } from '../core/layout'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { startDaemon } from './daemon'
import { LiveAccess } from './live-access'

it.each(['sibling tier', 'concurrent edit'])('limits read-only OAuth writeback with a %s', async (scenario) => {
  const shortTmp = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
  mkdirSync(shortTmp, { recursive: true })
  const root = mkdtempSync(join(shortTmp, 'tvo-'))
  const dir = join(root, 'vault')
  const env = { TYPEVAULT_DIR: dir, XDG_CONFIG_HOME: root }
  const layout = globalLayout(env)
  const requested = Promise.withResolvers<void>()
  const proceed = Promise.withResolvers<void>()
  const endpoint = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    async fetch() {
      requested.resolve()
      await proceed.promise
      return Response.json({ access_token: 'fixture-refreshed', refresh_token: 'fixture-rotated', expires_in: 3600 })
    },
  })
  let daemon: Awaited<ReturnType<typeof startDaemon>> | undefined
  try {
    const { identity } = await createIdentity('owner', 'machine')
    const { owner } = await initGlobalVault(founderOf(identity), env)
    const vault = await Vault.open(layout, [owner], env)
    const admin = new Admin(vault)
    await admin.addTier('member')
    await admin.addTier('trusted')
    await admin.include('trusted', 'member')
    const name = parseEntryName('fixture/oauth')
    const secret = (value: string) => ({ key: { type: 'secret' as const, value } })
    const high =
      scenario === 'sibling tier'
        ? await vault.put({ name, tier: 'trusted', fields: secret('fixture-protected') }, signerOf(owner))
        : undefined
    const key = await vault.keyring.unlock('member')
    if (key === undefined) throw new Error('missing member key')
    const member = await Vault.open(layout, [key], env)
    const lower = await member.put(
      {
        name,
        tier: 'member',
        fields: {
          key: {
            type: 'oauth',
            value: {
              access_token: 'fixture-expired',
              refresh_token: 'fixture-refresh',
              token_url: endpoint.url.href,
              expires_at: '2020-01-01T00:00:00.000Z',
            },
          },
        },
      },
      signerOf(key),
    )
    daemon = await startDaemon({ layout, env, keys: [owner] })
    const token = await createAdmin({ dir, env }).grant({ tiers: ['member'], only: [name], readOnly: true })
    const result = new LiveAccess(layout.agentSocket, token).values([])
    if (high === undefined) {
      // If the daemon rejects before refreshing, fail without waiting for a request that cannot arrive.
      await Promise.race([
        requested.promise,
        result.then(() => {
          throw new Error('refresh did not run')
        }),
      ])
      const edited = await member.put({ name, tier: 'member', fields: secret('fixture-edited') }, signerOf(key))
      proceed.resolve()
      await expect(result).rejects.toMatchObject({ code: 'conflict' })
      expect(await member.find(name)).toEqual(edited)
    } else {
      proceed.resolve()
      await expect(result).resolves.toMatchObject([
        {
          id: lower.envelope.id,
          fields: {
            key: { type: 'oauth', value: { access_token: 'fixture-refreshed', refresh_token: 'fixture-rotated' } },
          },
        },
      ])
      expect(await vault.find(name)).toEqual(high)
      expect((await member.find(name))?.envelope.rev).toBe(lower.envelope.rev + 1)
    }
  } finally {
    proceed.resolve()
    try {
      await endpoint.stop(true)
      await daemon?.stop()
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }
})
