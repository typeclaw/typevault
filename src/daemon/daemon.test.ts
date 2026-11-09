import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { z } from 'zod'

import { envFor } from '../access/env'
import { ScopedVault } from '../access/scoped'
import { readAudit } from '../audit/log'
import { Admin } from '../core/admin'
import { seal, type SecretKey } from '../core/crypto'
import { utf8 } from '../core/encoding'
import { signerOf } from '../core/entries'
import { createIdentity } from '../core/identity'
import { type Founder, founderOf, initGlobalVault } from '../core/init'
import { globalLayout, type Layout } from '../core/layout'
import { holdLock, isLockHeld } from '../core/lock'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { callDaemon } from './client'
import { type RunningDaemon, startDaemon } from './daemon'
import { GrantStore, MAX_CHAIN } from './grants'
import { LiveAccess } from './live-access'
import { PromptRequests } from './requests'

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

const machineFounder = async (): Promise<Founder> => founderOf((await createIdentity('owner', 'machine')).identity)

let base: string
let env: Record<string, string>
let layout: Layout
let owner: SecretKey
let daemon: RunningDaemon
const n = parseEntryName
const Token = z.object({ token: z.string() })

const grant = (socket: string, body: Record<string, unknown>) =>
  callDaemon(layout.adminSocket(socket), '/v1/grant', body, Token)

beforeEach(async () => {
  base = mkdtempSync(join(SHORT_TMP, 'tvd-'))
  env = { TYPEVAULT_DIR: join(base, 'vault'), XDG_CONFIG_HOME: base }
  layout = globalLayout(env)
  owner = (await initGlobalVault(await machineFounder(), env)).owner
  const vault = await Vault.open(layout, [owner], {})
  const admin = new Admin(vault)
  await admin.addTier('member')
  await admin.addTier('trusted')
  await admin.include('trusted', 'member')
  await admin.setCeiling('bot', 'member')
  await vault.put(
    { name: n('github/bot'), fields: { password: { type: 'secret' as const, value: 'hunter2-bot' } }, tier: 'member' },
    signerOf(owner),
  )
  await vault.put(
    { name: n('openai'), fields: { key: { type: 'secret' as const, value: 'sk-test-openai' } }, tier: 'member' },
    signerOf(owner),
  )
  await vault.put(
    { name: n('stripe'), fields: { key: { type: 'secret' as const, value: 'sk_live_x' } }, tier: 'trusted' },
    signerOf(owner),
  )
  daemon = await startDaemon({ layout, env, keys: [owner] })
})

afterEach(async () => {
  try {
    await daemon.stop()
  } finally {
    rmSync(base, { recursive: true, force: true })
  }
})

it('stops cleanly when the host asks it to over the control socket', async () => {
  // given a runner that stops the daemon as soon as it is asked to, as `typevault daemon run` does
  const stopped = daemon.stopRequested.then(() => daemon.stop())

  // when the host asks over the control socket, as stopDaemon does on Windows
  await callDaemon(layout.controlSocket, '/v1/shutdown', {}, z.object({ ok: z.literal(true) }))

  // then the daemon finishes stopping and lets go of its lock (the test times out if stopping hangs)
  await stopped
  expect(isLockHeld(layout.daemonLock)).toBe(false)
  daemon = await startDaemon({ layout, env, keys: [owner] })
})

it('refuses to stop for a caller on the agent socket, which sandboxes reach', async () => {
  await expect(callDaemon(layout.agentSocket, '/v1/shutdown', {}, z.json())).rejects.toMatchObject({
    code: 'not_found',
  })

  expect(await callDaemon(layout.agentSocket, '/v1/ping', {}, z.object({ ok: z.literal(true) }))).toMatchObject({
    ok: true,
  })
})

describe('live grants', () => {
  it('keeps a malformed request body distinct from a corrupt manifest', async () => {
    const response = await fetch('http://typevault/v1/grant', {
      unix: layout.adminSocket('default'),
      method: 'POST',
      body: '{',
    })
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: { code: 'invalid' } })

    const { token } = await grant('default', { tiers: ['member'] })
    writeFileSync(layout.tiersFile, '<<<<<<< HEAD\n{}\n=======\n{}\n>>>>>>> branch\n')
    await expect(new LiveAccess(layout.agentSocket, token).list()).rejects.toMatchObject({
      code: 'tampered',
      message: expect.stringContaining(layout.tiersFile),
    })
  })

  it.each(['0s', '99999999999d'])('rejects TTL %s through the admin socket', async (ttl) => {
    await expect(grant('default', { tiers: ['member'], ttl })).rejects.toMatchObject({ code: 'invalid' })
  })

  it('serves values within the grant and audits each read with its label', async () => {
    const { token } = await grant('default', { tiers: ['member'], label: 'session:abc' })
    const access = new LiveAccess(layout.agentSocket, token)
    expect((await access.list()).map((e): string => e.name).sort()).toEqual(['github/bot', 'openai'])
    expect((await access.get(n('openai'))).fields).toEqual({
      key: { type: 'secret' as const, value: 'sk-test-openai' },
    })
    expect(readAudit(layout).at(-1)).toMatchObject({
      action: 'read',
      mode: 'live',
      label: 'session:abc',
      entries: ['openai'],
    })
  })

  it('refuses a grant above the socket ceiling', async () => {
    await expect(grant('bot', { tiers: ['trusted'] })).rejects.toMatchObject({ code: 'denied' })
  })

  it('holds a running socket to its ceiling as the owner lowers or removes it', async () => {
    // given the bot socket already serving under a `member` ceiling
    expect((await grant('bot', { tiers: ['member'] })).token).toBeString()
    const admin = new Admin(await Vault.open(layout, [owner], {}))

    // when the owner lowers it to a tier below `member`
    await admin.addTier('guest')
    await admin.setCeiling('bot', 'guest')

    // then the socket refuses `member` but grants `guest`
    await expect(grant('bot', { tiers: ['member'] })).rejects.toMatchObject({ code: 'denied' })
    expect((await grant('bot', { tiers: ['guest'] })).token).toBeString()

    // and once the ceiling is removed, it grants nothing
    await admin.removeCeiling('bot')
    await expect(grant('bot', { tiers: ['guest'] })).rejects.toMatchObject({ code: 'denied' })
  })

  it('caps the owner socket while the owner signs a default ceiling, and uncaps it once removed', async () => {
    // given the uncapped owner socket, and the owner signing a `member` ceiling for it while running
    const admin = new Admin(await Vault.open(layout, [owner], {}))
    await admin.setCeiling('default', 'member')

    // then it refuses `trusted` and the audit trail
    await expect(grant('default', { tiers: ['trusted'] })).rejects.toMatchObject({ code: 'denied' })
    await expect(callDaemon(layout.adminSocket('default'), '/v1/audit', {}, z.json())).rejects.toMatchObject({
      code: 'denied',
    })

    // and once the ceiling is removed, it is uncapped again
    await admin.removeCeiling('default')
    expect((await grant('default', { tiers: ['trusted'] })).token).toBeString()
    expect(await callDaemon(layout.adminSocket('default'), '/v1/audit', {}, z.array(z.json()))).toBeArray()
  })

  it('narrows a derived grant and revokes it with its parent', async () => {
    const { token } = await grant('default', { tiers: ['member'], label: 'agent:a' })
    const parent = new LiveAccess(layout.agentSocket, token)
    const derived = await parent.call('/v1/derive', { only: ['github/*'] }, Token)
    const child = new LiveAccess(layout.agentSocket, derived.token)
    expect((await child.list()).map((e): string => e.name)).toEqual(['github/bot'])
    await callDaemon(layout.adminSocket('default'), '/v1/revoke', { label: 'agent:a' }, z.json())
    await expect(child.list()).rejects.toMatchObject({ code: 'denied' })
  })

  it('refuses a grant or derive with too many or too long --only patterns', async () => {
    const many = Array.from({ length: 101 }, (_, i) => `entry-${i}`)
    await expect(grant('default', { tiers: ['member'], only: many })).rejects.toMatchObject({ code: 'invalid' })
    const { token } = await grant('default', { tiers: ['member'] })
    const parent = new LiveAccess(layout.agentSocket, token)
    await expect(parent.call('/v1/derive', { only: many }, Token)).rejects.toMatchObject({ code: 'invalid' })
    await expect(parent.call('/v1/derive', { only: ['a'.repeat(257)] }, Token)).rejects.toMatchObject({
      code: 'invalid',
    })
    expect((await parent.call('/v1/derive', { only: many.slice(0, 100) }, Token)).token).toStartWith('tvl1.')
    await expect(parent.values(many)).rejects.toMatchObject({ code: 'invalid' })
    await expect(parent.values(['a'.repeat(257)])).rejects.toMatchObject({ code: 'invalid' })
    expect(await parent.values([...many.slice(0, 99), 'a'.repeat(256)])).toEqual([])
  })

  it('refuses a grant or derive with too many or too long tiers', async () => {
    const many = Array.from({ length: 101 }, () => 'member')
    await expect(grant('default', { tiers: many })).rejects.toMatchObject({ code: 'invalid' })
    await expect(grant('default', { tiers: ['a'.repeat(257)] })).rejects.toMatchObject({ code: 'invalid' })
    const { token } = await grant('default', { tiers: ['member'] })
    const parent = new LiveAccess(layout.agentSocket, token)
    await expect(parent.call('/v1/derive', { tiers: many }, Token)).rejects.toMatchObject({ code: 'invalid' })
    expect((await parent.call('/v1/derive', { tiers: many.slice(0, 100) }, Token)).token).toStartWith('tvl1.')
  })

  it(`refuses to derive a grant more than ${MAX_CHAIN - 1} levels deep`, async () => {
    let { token } = await grant('default', { tiers: ['member'] })
    for (let depth = 1; depth < MAX_CHAIN; depth++) {
      ;({ token } = await new LiveAccess(layout.agentSocket, token).call('/v1/derive', {}, Token))
    }
    const deepest = new LiveAccess(layout.agentSocket, token)
    expect((await deepest.list()).length).toBe(2)
    await expect(deepest.call('/v1/derive', {}, Token)).rejects.toMatchObject({ code: 'invalid' })
  })

  it('keeps a capped socket away from grants it did not issue and from the audit trail', async () => {
    const { token } = await grant('default', { tiers: ['member'], label: 'owner:session' })
    const bot = layout.adminSocket('bot')
    await callDaemon(bot, '/v1/revoke', { label: 'owner:session' }, z.json())
    expect((await new LiveAccess(layout.agentSocket, token).list()).length).toBe(2)
    expect(await callDaemon(bot, '/v1/grants', {}, z.array(z.json()))).toEqual([])
    await expect(callDaemon(bot, '/v1/audit', {}, z.json())).rejects.toMatchObject({ code: 'denied' })
  })

  it('rejects an unknown token', async () => {
    await expect(new LiveAccess(layout.agentSocket, 'tvl1.nope.nope').list()).rejects.toMatchObject({ code: 'denied' })
  })

  it('remembers what a grant read, for redaction', async () => {
    const { token } = await grant('default', { tiers: ['member'] })
    const access = new LiveAccess(layout.agentSocket, token)
    await access.get(n('github/bot'))
    expect(await access.readValues()).toEqual(['hunter2-bot'])
  })
})

describe('secret prompt', () => {
  it('retries failed binds on the next request without restarting (#53)', async () => {
    await daemon.stop()
    const other = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: () => new Response('other') })
    const port = other.port
    try {
      if (port === undefined) throw new Error('Expected a TCP listener')
      daemon = await startDaemon({ layout, env, keys: [owner], prompt: { port } })
      const { token } = await grant('default', { tiers: ['member'] })
      const access = new LiveAccess(layout.agentSocket, token)
      const request = () =>
        access.call(
          '/v1/request',
          { name: 'resend', preset: 'api_key', reason: 'mail' },
          z.object({ id: z.string(), url: z.string(), code: z.string() }),
        )
      // Both requests share startup; neither failure may poison the next attempt.
      await Promise.all([
        expect(request()).rejects.toMatchObject({ code: 'unavailable' }),
        expect(request()).rejects.toMatchObject({ code: 'unavailable' }),
      ])
      await other.stop(true)

      const opened = await request()

      expect(new URL(opened.url).port).toBe(String(port))
      expect((await fetch(opened.url, { signal: AbortSignal.timeout(5_000) })).status).toBe(200)
    } finally {
      await other.stop(true)
    }
  })

  it('finishes lock cleanup after a failed prompt bind (#53)', async () => {
    await daemon.stop()
    const other = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: () => new Response('other') })
    try {
      const port = other.port
      if (port === undefined) throw new Error('Expected a TCP listener')
      daemon = await startDaemon({ layout, env, keys: [owner], prompt: { port } })
      const { token } = await grant('default', { tiers: ['member'] })
      await expect(
        new LiveAccess(layout.agentSocket, token).call('/v1/request', { name: 'resend', reason: 'mail' }, z.json()),
      ).rejects.toMatchObject({ code: 'unavailable' })

      await daemon.stop()

      const files = [
        layout.agentSocket,
        layout.controlSocket,
        ...daemon.ceilings.map((ceiling) => layout.adminSocket(ceiling.name)),
        join(layout.run, 'daemon.pid'),
      ]
      expect(files.filter((file) => existsSync(file))).toEqual([])
      expect(isLockHeld(layout.daemonLock)).toBe(false)
      // Stopping leaves the committed anchors alone: they only change every 100th audit record.
      expect(existsSync(layout.anchorsFile)).toBe(false)
      daemon = await startDaemon({ layout, env, keys: [owner] })
    } finally {
      await other.stop(true)
    }
  })

  it('stores what the page submits, encrypted to the tier, without the daemon seeing plaintext', async () => {
    const { token } = await grant('default', { tiers: ['member'], label: 'session:p' })
    const access = new LiveAccess(layout.agentSocket, token)
    const opened = await access.call(
      '/v1/request',
      { name: 'resend', preset: 'api_key', reason: 'send mail' },
      z.object({ id: z.string(), url: z.string(), code: z.string() }),
    )
    const vault = await Vault.open(layout, [owner], {})
    const recipients = [vault.state.tiers['member']?.recipient ?? '', vault.state.owner.recipient]
    const now = new Date().toISOString()
    const payload = {
      v: 1,
      name: 'resend',

      fields: { key: { type: 'secret' as const, value: 're_test_1' } },
      tags: [],
      created: now,
      rotated: now,
    }
    const body = await seal(recipients, utf8(JSON.stringify(payload)))
    const posting = fetch(opened.url, {
      method: 'POST',
      body: new Uint8Array(body),
      headers: { 'content-type': 'application/octet-stream' },
    })
    const done = await access.call('/v1/request/wait', { id: opened.id }, z.object({ stored: z.string() }))
    const posted = await posting
    expect(posted.status).toBe(204)
    expect(done.stored).toBe('resend')
    expect((await access.get(n('resend'))).fields).toEqual({ key: { type: 'secret' as const, value: 're_test_1' } })
  })

  it('returns a stored result after a timed-out waiter reconnects', async () => {
    const vault = await Vault.open(layout, [owner], {})
    const { record } = new GrantStore(layout.grantsFile).issue({
      tiers: ['member'],
      only: [],
      ttlMs: 60_000,
      label: 'session:retry',
      ceiling: 'default',
    })
    const chain = [{ tiers: record.tiers, only: record.only }]
    const access = new ScopedVault(vault, chain, {
      mode: 'live',
      grant: record.id,
      label: record.label,
      ownTiers: record.tiers,
      defaultTier: 'member',
    })
    const requests = new PromptRequests(vault, {})
    try {
      const opened = await requests.open(
        { chain, grant: record, access, isLive: () => true },
        { name: n('resend'), preset: 'api_key', reason: 'send mail' },
      )
      const abandoned = requests.wait(record.id, opened.id)
      const timeout = AbortSignal.timeout(10)
      const timedOut = new Promise<never>((_resolve, reject) => {
        timeout.addEventListener('abort', () => reject(timeout.reason), { once: true })
      })
      await expect(Promise.race([abandoned, timedOut])).rejects.toMatchObject({ name: 'TimeoutError' })

      const recipients = [vault.state.tiers['member']?.recipient ?? '', vault.state.owner.recipient]
      const now = new Date().toISOString()
      const payload = {
        v: 1,
        name: 'resend',
        fields: { key: { type: 'secret' as const, value: 're_test_retry' } },
        tags: [],
        created: now,
        rotated: now,
      }
      const body = new Uint8Array(await seal(recipients, utf8(JSON.stringify(payload))))
      expect(
        (
          await fetch(opened.url, {
            method: 'POST',
            body,
            headers: { 'content-type': 'application/octet-stream' },
          })
        ).status,
      ).toBe(204)
      expect(await abandoned).toBe(n('resend'))

      expect(await requests.wait(record.id, opened.id)).toBe(n('resend'))
      expect(
        (
          await fetch(opened.url, {
            method: 'POST',
            body,
            headers: { 'content-type': 'application/octet-stream' },
          })
        ).status,
      ).toBe(410)
    } finally {
      await requests.stop()
    }
  })
})

it('refuses a prompt submission for a different entry than the one requested', async () => {
  const { token } = await grant('default', { tiers: ['member'], only: ['resend'] })
  const access = new LiveAccess(layout.agentSocket, token)
  const opened = await access.call(
    '/v1/request',
    { name: 'resend', preset: 'api_key', reason: 'mail' },
    z.object({ id: z.string(), url: z.string(), code: z.string() }),
  )
  const vault = await Vault.open(layout, [owner], {})
  const recipients = [vault.state.tiers['member']?.recipient ?? '', vault.state.owner.recipient]
  const now = new Date().toISOString()
  const forged = {
    v: 1,
    name: 'openai',

    fields: { key: { type: 'secret' as const, value: 'forged' } },
    tags: [],
    created: now,
    rotated: now,
  }
  const body = new Uint8Array(await seal(recipients, utf8(JSON.stringify(forged))))
  const posted = fetch(opened.url, { method: 'POST', body, headers: { 'content-type': 'application/octet-stream' } })
  await expect(
    access.call('/v1/request/wait', { id: opened.id }, z.object({ stored: z.string() })),
  ).rejects.toMatchObject({
    code: 'tampered',
  })
  const rejected = await posted
  expect(rejected.status).toBe(422)
  expect(rejected.headers.get('content-type')).toContain('text/html')
  expect(readAudit(layout).at(-1)).toMatchObject({
    action: 'request.rejected',
    grant: expect.any(String),
    entries: ['resend'],
  })
  expect((await vault.find(n('openai')))?.payload.fields).toEqual({
    key: { type: 'secret' as const, value: 'sk-test-openai' },
  })
})

// Windows sockets take the run directory's ACL and have no Unix mode to check.
it.skipIf(process.platform === 'win32')('keeps sockets private to the owner', async () => {
  const { mode } = await Bun.file(join(layout.run, 'agent.sock')).stat()
  expect(mode & 0o777).toBe(0o600)
})

it('checks an import against tiers as they are when it writes, not as the daemon last read them', async () => {
  // given a trusted grant the daemon has already served while trusted included member
  const access = new LiveAccess(layout.agentSocket, (await grant('default', { tiers: ['trusted'] })).token)
  await access.list()

  // when another process drops that include, and the grant imports into member right away
  await new Admin(await Vault.open(layout, [owner], {})).exclude('trusted', 'member')
  const importing = access.importEntries(
    [{ name: n('acme/new'), fields: { key: { type: 'secret', value: 'v' } }, tags: [], source: 'csv:1' }],
    'member',
  )

  // then it is refused, and nothing is written
  await expect(importing).rejects.toMatchObject({ code: 'denied' })
  expect(await (await Vault.open(layout, [owner], {})).find(n('acme/new'))).toBeUndefined()
})

describe('unlocked session', () => {
  it.each([
    ['lower', 'owner'],
    ['lower', 'higher'],
    ['owner', 'owner'],
    ['owner', 'higher'],
  ] as const)('preserves %s-written env trust when the %s reader refreshes OAuth', async (writer, refresher) => {
    let refreshes = 0
    const endpoint = Bun.serve({
      port: 0,
      hostname: '127.0.0.1',
      fetch: () => {
        refreshes++
        return Response.json({ access_token: 'fresh-token', expires_in: 3600 })
      },
    })
    try {
      await daemon.stop()
      daemon = await startDaemon({ layout, env, keys: [owner], session: { ttlMs: 60_000 } })
      const session = new LiveAccess(layout.agentSocket, readFileSync(layout.sessionFile, 'utf8'))
      const lower = new LiveAccess(layout.agentSocket, (await grant('default', { tiers: ['member'] })).token)
      const higher = new LiveAccess(layout.agentSocket, (await grant('default', { tiers: ['trusted'] })).token)
      await (writer === 'owner' ? session : lower).set({
        name: n('custom'),
        tier: 'member',
        env: 'MY_CUSTOM_KEY',
        fields: {
          $default: { type: 'secret', value: 'original-default' },
          session: {
            type: 'oauth',
            value: {
              access_token: 'stale-token',
              refresh_token: 'refresh-token',
              expires_at: '2000-01-01T00:00:00.000Z',
              token_url: `http://127.0.0.1:${endpoint.port}/token`,
            },
          },
        },
      })
      const expected = {
        [writer === 'owner' ? 'MY_CUSTOM_KEY' : 'CUSTOM']: 'original-default',
        CUSTOM_SESSION: 'fresh-token',
      }
      const readers = { owner: session, higher }
      const environment = async (reader: LiveAccess) =>
        envFor(await reader.values(['custom']), new Date(), {
          ownTiers: await reader.ownTiers(),
          explicit: ['custom'],
        })

      // The triggering read and later owner/higher reads must agree on the original metadata's authority.
      expect(await environment(readers[refresher])).toEqual(expected)
      for (const reader of [session, higher]) expect(await environment(reader)).toEqual(expected)
      const stored = await (await Vault.open(layout, [owner], {})).find(n('custom'))
      expect(stored?.payload.fields['session']?.value).toMatchObject({ access_token: 'fresh-token' })
      expect(refreshes).toBe(1)
    } finally {
      await endpoint.stop(true)
    }
  })

  it('serves its grant from run/session.token and ends it with the daemon', async () => {
    // given a daemon started as an unlocked session
    await daemon.stop()
    daemon = await startDaemon({ layout, env, keys: [owner], session: { ttlMs: 60_000 } })
    const token = readFileSync(layout.sessionFile, 'utf8')

    // then the session reads everything its key reaches
    const names = (await new LiveAccess(layout.agentSocket, token).list()).map((e): string => e.name).sort()
    expect(names).toEqual(['github/bot', 'openai', 'stripe'])

    // and when it stops, the token file and the grant are gone for good
    await daemon.stop()
    expect(existsSync(layout.sessionFile)).toBe(false)
    daemon = await startDaemon({ layout, env, keys: [owner] })
    await expect(new LiveAccess(layout.agentSocket, token).list()).rejects.toMatchObject({ code: 'denied' })
  })

  it('imports through the session in one transaction, and never past a grant', async () => {
    // given a daemon started as an unlocked session, and a grant for member only
    await daemon.stop()
    daemon = await startDaemon({ layout, env, keys: [owner], session: { ttlMs: 60_000 } })
    const session = new LiveAccess(layout.agentSocket, readFileSync(layout.sessionFile, 'utf8'))
    const member = new LiveAccess(layout.agentSocket, (await grant('default', { tiers: ['member'] })).token)
    const item = (name: string, source: string) => ({
      name: n(name),
      fields: { key: { type: 'secret' as const, value: `value of ${name}` } },
      tags: [],
      source,
    })

    // when the session imports two items
    const stored = await session.importEntries([item('acme/one', 'csv:1'), item('acme/two', 'csv:2')], 'member')

    // then both land in member, audited as one import
    expect(stored.map((e): string => e.name)).toEqual(['acme/one', 'acme/two'])
    expect(readAudit(layout).at(-1)).toMatchObject({
      action: 'import',
      mode: 'live',
      tiers: ['member'],
      entries: ['acme/one', 'acme/two'],
    })
    expect((await member.get(n('acme/two'))).fields['key']?.value).toBe('value of acme/two')

    // and the member grant can't take over stripe, which only trusted reaches, nor write anything with it
    await expect(
      member.importEntries([item('acme/three', 'csv:3'), item('stripe', 'csv:4')], 'member'),
    ).rejects.toMatchObject({ code: 'denied' })
    const vault = await Vault.open(layout, [owner], {})
    expect((await vault.find(n('stripe')))?.envelope.tier).toBe('trusted')
    expect(await vault.find(n('acme/three'))).toBeUndefined()
  })

  it('imports more than one request body can carry, even in a single entry, as one transaction', async () => {
    // given an unlocked session, and three items, one of them alone over 1 MiB once serialized
    await daemon.stop()
    daemon = await startDaemon({ layout, env, keys: [owner], session: { ttlMs: 60_000 } })
    const session = new LiveAccess(layout.agentSocket, readFileSync(layout.sessionFile, 'utf8'))
    const sizes = { one: 1_200_000, two: 600_000, three: 10 }
    const items = Object.entries(sizes).map(([name, size], index) => ({
      name: n(`big/${name}`),
      fields: { note: { type: 'text' as const, value: 'é'.repeat(size / 2) } },
      tags: [],
      source: `csv:${index}`,
    }))

    // when the session imports them
    const stored = await session.importEntries(items, 'member')

    // then all three land, audited as one import
    expect(stored.map((e): string => e.name)).toEqual(['big/one', 'big/two', 'big/three'])
    expect(readAudit(layout).filter((record) => record['action'] === 'import')).toHaveLength(1)
    const big = await (await Vault.open(layout, [owner], {})).find(n('big/one'))
    expect(big?.payload.fields['note']?.value).toBe('é'.repeat(600_000))
  })

  it('stays out of reach of a ceiling named "session"', async () => {
    // given an owner-signed ceiling named "session", and a daemon started as an unlocked session
    await daemon.stop()
    await new Admin(await Vault.open(layout, [owner], {})).setCeiling('session', 'member')
    daemon = await startDaemon({
      layout,
      env,
      keys: [owner],
      session: { ttlMs: 60_000 },
    })
    const token = readFileSync(layout.sessionFile, 'utf8')
    const socket = layout.adminSocket('session')

    // when that ceiling's socket lists grants and revokes the session by label
    const listed = await callDaemon(socket, '/v1/grants', {}, z.array(z.json()))
    await callDaemon(socket, '/v1/revoke', { label: 'session' }, z.json())

    // then it saw nothing, and the session still reads
    expect(listed).toEqual([])
    expect((await new LiveAccess(layout.agentSocket, token).list()).length).toBe(3)
  })

  it('treats grants from a ceiling named "session" as ordinary grants', async () => {
    // given a ceiling named "session" over trusted, and a grant it issued for trusted
    await daemon.stop()
    await new Admin(await Vault.open(layout, [owner], {})).setCeiling('session', 'trusted')
    daemon = await startDaemon({ layout, env, keys: [owner] })
    const access = new LiveAccess(layout.agentSocket, (await grant('session', { tiers: ['trusted'] })).token)

    // when it writes without naming a tier
    const written = await access.set({ name: n('resend'), fields: { key: { type: 'secret', value: 're_x' } } })

    // then it owns only trusted, and the write lands there
    expect(await access.ownTiers()).toEqual(['trusted'])
    expect(written.tier).toBe('trusted')
  })
})

describe('daemon lock', () => {
  it('is held for the life of the daemon and released once it has stopped', async () => {
    expect(isLockHeld(layout.daemonLock)).toBe(true)

    await daemon.stop()

    expect(isLockHeld(layout.daemonLock)).toBe(false)
    daemon = await startDaemon({ layout, env, keys: [owner] })
  })

  it('keeps a new daemon from starting while another still holds it, shutting down', async () => {
    // given the running daemon stopped, and its lock still held as if its cleanup were unfinished
    await daemon.stop()
    const release = holdLock(layout.daemonLock)
    if (release === undefined) throw new Error('the lock was not free after stop')

    // then a new daemon refuses to start beside it
    await expect(startDaemon({ layout, env, keys: [owner] })).rejects.toMatchObject({ code: 'conflict' })
    release()
    daemon = await startDaemon({ layout, env, keys: [owner] })
  })
})
