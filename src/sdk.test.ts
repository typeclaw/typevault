import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { createClient, parseEntryName } from 'typevault'
import { createAdmin } from 'typevault/admin'
import { createRedactor } from 'typevault/redact'

import { Admin } from './core/admin'
import type { SecretKey } from './core/crypto'
import { signerOf } from './core/entries'
import { initVault } from './core/init'
import { layoutOf } from './core/layout'
import { Vault } from './core/vault'
import { type RunningDaemon, startDaemon } from './daemon/daemon'

let root: string
let owner: SecretKey
let daemon: RunningDaemon
const n = parseEntryName

beforeEach(async () => {
  // Short root: unix socket paths are limited to ~104 bytes.
  root = mkdtempSync('/tmp/tvs-')
  owner = await initVault(root)
  const vault = await Vault.open(layoutOf(root), [owner], {})
  const admin = new Admin(vault)
  await admin.addTier('member')
  await admin.addTier('trusted')
  await admin.include('trusted', 'member')
  await vault.put(
    { name: n('openai'), type: 'api_key', fields: { key: 'sk-test-openai' }, tier: 'member' },
    signerOf(owner),
  )
  await vault.put(
    { name: n('stripe'), type: 'api_key', fields: { key: 'sk_live_x' }, tier: 'trusted' },
    signerOf(owner),
  )
  daemon = await startDaemon({ layout: layoutOf(root), env: { TYPEVAULT_DIR: root } })
})

afterEach(async () => {
  await daemon.stop()
  rmSync(root, { recursive: true, force: true })
})

describe('sdk', () => {
  it('issues a live grant and reads through it', async () => {
    const admin = createAdmin({ dir: root, env: {} })
    const grant = await admin.grant({ tiers: ['member'], label: 'sdk:test' })
    const client = await createClient({ grant, dir: root, env: {} })
    expect((await client.list()).map((entry): string => entry.name)).toEqual(['openai'])
    expect((await client.get(n('openai'))).fields).toEqual({ key: 'sk-test-openai' })
    const redactor = createRedactor(await client.readValues())
    expect(redactor.redact('key=sk-test-openai')).toBe('key=[redacted]')
  })

  it('reads a sealed grant without the daemon round trip', async () => {
    const grant = await createAdmin({ dir: root, env: {} }).grant({ tiers: ['member'], sealed: true })
    expect(grant.startsWith('tvg1:')).toBe(true)
    const client = await createClient({ grant, dir: root, env: {} })
    expect((await client.get(n('openai'))).fields).toEqual({ key: 'sk-test-openai' })
  })

  it('lists and revokes grants by label', async () => {
    const admin = createAdmin({ dir: root, env: {} })
    const grant = await admin.grant({ tiers: ['member'], label: 'sdk:revoke' })
    expect((await admin.list()).map((info) => info.label)).toContain('sdk:revoke')
    expect(await admin.revoke({ label: 'sdk:revoke' })).toHaveLength(1)
    const client = await createClient({ grant, dir: root, env: {} })
    await expect(client.list()).rejects.toMatchObject({ code: 'denied' })
  })

  it('reaches the global vault only when global is asked for', async () => {
    // given a global vault under XDG_CONFIG_HOME and no project vault around
    const config = mkdtempSync('/tmp/tvx-')
    const globalRoot = join(config, 'typevault')
    const key = await initVault(globalRoot)
    const vault = await Vault.open(layoutOf(globalRoot), [key], {})
    await new Admin(vault).addTier('member')
    await vault.put({ name: n('openai'), type: 'api_key', fields: { key: 'sk-global' }, tier: 'member' }, signerOf(key))
    const env = { XDG_CONFIG_HOME: config }
    // This repo dogfoods its own .typevault/, so leave it for a directory with none.
    const cwd = process.cwd()
    process.chdir(config)

    // then only global: true reads it
    try {
      await expect(createClient({ direct: true, env })).rejects.toMatchObject({ code: 'not_found' })
      const client = await createClient({ direct: true, global: true, env })
      expect((await client.get(n('openai'))).fields).toEqual({ key: 'sk-global' })
    } finally {
      process.chdir(cwd)
      rmSync(config, { recursive: true, force: true })
    }
  })

  it('refuses local keys unless direct mode is asked for', async () => {
    await expect(createClient({ dir: root, env: {} })).rejects.toMatchObject({ code: 'denied' })
    const client = await createClient({ dir: root, env: {}, direct: true })
    expect((await client.get(n('stripe'))).fields).toEqual({ key: 'sk_live_x' })
  })
})
