import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { createClient, parseEntryName } from 'typevault'
import { createAdmin } from 'typevault/admin'
import { createRedactor } from 'typevault/redact'

import { Admin } from './core/admin'
import type { SecretKey } from './core/crypto'
import { signerOf } from './core/entries'
import { createIdentity, writeIdentity } from './core/identity'
import { founderOf, initGlobalVault } from './core/init'
import { globalLayout } from './core/layout'
import { Vault } from './core/vault'
import { type RunningDaemon, startDaemon } from './daemon/daemon'
import { stopDaemon } from './daemon/spawn'

let root: string
let owner: SecretKey
let daemon: RunningDaemon
const n = parseEntryName

type Env = Record<string, string>

/** A global vault owned by a machine identity, the way a CI host or agent box holds its key. */
async function machineVault(env: Env): Promise<SecretKey> {
  const { identity } = await createIdentity('owner', 'machine')
  writeIdentity(env, identity)
  return (await initGlobalVault(founderOf(identity), env)).owner
}

const envIn = (root: string): Env => ({ TYPEVAULT_DIR: join(root, 'vault'), XDG_CONFIG_HOME: root })
const at = (root: string) => ({ dir: join(root, 'vault'), env: { XDG_CONFIG_HOME: root } })

beforeEach(async () => {
  // Short root: unix socket paths are limited to ~104 bytes.
  root = mkdtempSync('/tmp/tvs-')
  owner = await machineVault(envIn(root))
  const vault = await Vault.open(globalLayout(envIn(root)), [owner], {})
  const admin = new Admin(vault)
  await admin.addTier('member')
  await admin.addTier('trusted')
  await admin.include('trusted', 'member')
  await vault.put(
    { name: n('openai'), fields: { key: { type: 'secret' as const, value: 'sk-test-openai' } }, tier: 'member' },
    signerOf(owner),
  )
  await vault.put(
    { name: n('stripe'), fields: { key: { type: 'secret' as const, value: 'sk_live_x' } }, tier: 'trusted' },
    signerOf(owner),
  )
  daemon = await startDaemon({ layout: globalLayout(envIn(root)), env: envIn(root), keys: [owner] })
})

afterEach(async () => {
  await daemon.stop()
  rmSync(root, { recursive: true, force: true })
})

describe('sdk', () => {
  it('issues a live grant and reads through it', async () => {
    const admin = createAdmin(at(root))
    const grant = await admin.grant({ tiers: ['member'], label: 'sdk:test' })
    const client = await createClient({ grant, ...at(root) })
    expect((await client.list()).map((entry): string => entry.name)).toEqual(['openai'])
    expect((await client.get(n('openai'))).fields).toEqual({
      key: { type: 'secret' as const, value: 'sk-test-openai' },
    })
    const redactor = createRedactor(await client.readValues())
    expect(redactor.redact('key=sk-test-openai')).toBe('key=[redacted]')
  })

  it('reads a sealed grant without the daemon round trip', async () => {
    const grant = await createAdmin(at(root)).grant({ tiers: ['member'], sealed: true })
    expect(grant.startsWith('tvg1:')).toBe(true)
    const client = await createClient({ grant, ...at(root) })
    expect((await client.get(n('openai'))).fields).toEqual({
      key: { type: 'secret' as const, value: 'sk-test-openai' },
    })
  })

  it('lists and revokes grants by label', async () => {
    const admin = createAdmin(at(root))
    const grant = await admin.grant({ tiers: ['member'], label: 'sdk:revoke' })
    expect((await admin.list()).map((info) => info.label)).toContain('sdk:revoke')
    expect(await admin.revoke({ label: 'sdk:revoke' })).toHaveLength(1)
    const client = await createClient({ grant, ...at(root) })
    await expect(client.list()).rejects.toMatchObject({ code: 'denied' })
  })

  it('reaches the global vault only when global is asked for', async () => {
    // given a global vault in the home directory and no project vault around
    const home = mkdtempSync('/tmp/tvx-')
    const env = { HOME: home, XDG_CONFIG_HOME: join(home, '.config') }
    const key = await machineVault(env)
    const vault = await Vault.open(globalLayout(env), [key], {})
    await new Admin(vault).addTier('member')
    await vault.put(
      { name: n('openai'), fields: { key: { type: 'secret' as const, value: 'sk-global' } }, tier: 'member' },
      signerOf(key),
    )
    // This repo dogfoods its own .typevault/, so leave it for a directory with none.
    const cwd = process.cwd()
    process.chdir(home)

    // then only global: true reads it
    try {
      await expect(createClient({ direct: true, env })).rejects.toMatchObject({ code: 'not_found' })
      const client = await createClient({ direct: true, global: true, env })
      expect((await client.get(n('openai'))).fields).toEqual({ key: { type: 'secret' as const, value: 'sk-global' } })
    } finally {
      process.chdir(cwd)
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('starts the global daemon where its caller looks for it, from an SDK env without HOME', async () => {
    // given a global vault whose private state lives under a HOME that is not the account's
    const home = mkdtempSync('/tmp/tvh-')
    const env = { HOME: home }
    const { identity } = await createIdentity('owner', 'machine')
    if (identity.kind !== 'machine') throw new Error('not a machine identity')
    const { owner: key } = await initGlobalVault(founderOf(identity), env)
    await new Admin(await Vault.open(globalLayout(env), [key], {})).addTier('member')
    const script = join(home, 'list.ts')
    await Bun.write(
      script,
      `import { createAdmin } from ${JSON.stringify(join(import.meta.dir, 'admin.ts'))}
const admin = createAdmin({ dir: ${JSON.stringify(join(home, '.typevault'))}, env: { TYPEVAULT_KEY: ${JSON.stringify(identity.key)} } })
console.log(JSON.stringify(await admin.list()))`,
    )

    try {
      // when a process started with that HOME lists grants with only the machine key, starting the daemon
      const run = Bun.spawn([process.execPath, script], {
        env: { HOME: home, PATH: process.env['PATH'] ?? '' },
        stdout: 'pipe',
        stderr: 'pipe',
      })
      const [code, out, err] = await Promise.all([
        run.exited,
        new Response(run.stdout).text(),
        new Response(run.stderr).text(),
      ])

      // then the daemon it started serves where it looks
      expect({ code, out: out.trim(), err }).toEqual({ code: 0, out: '[]', err: '' })
    } finally {
      await stopDaemon(globalLayout(env)).catch(() => undefined)
      rmSync(home, { recursive: true, force: true })
    }
  }, 20_000)

  it('refuses local keys unless direct mode is asked for', async () => {
    await expect(createClient(at(root))).rejects.toMatchObject({ code: 'denied' })
    const client = await createClient({ ...at(root), direct: true })
    expect((await client.get(n('stripe'))).fields).toEqual({ key: { type: 'secret' as const, value: 'sk_live_x' } })
  })
})
