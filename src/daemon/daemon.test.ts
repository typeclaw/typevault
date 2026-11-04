import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { readAudit } from '../audit/log'
import { Admin } from '../core/admin'
import { seal, type SecretKey } from '../core/crypto'
import { utf8 } from '../core/encoding'
import { signerOf } from '../core/entries'
import { createIdentity } from '../core/identity'
import { type Founder, founderOf, initVault } from '../core/init'
import { type Layout, layoutOf } from '../core/layout'
import { holdLock, isLockHeld } from '../core/lock'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { callDaemon } from './client'
import { type RunningDaemon, startDaemon } from './daemon'
import { LiveAccess } from './live-access'

const machineFounder = async (): Promise<Founder> => founderOf((await createIdentity('owner', 'machine')).identity)

let layout: Layout
let owner: SecretKey
let daemon: RunningDaemon
const n = parseEntryName
const Token = z.object({ token: z.string() })

const grant = (socket: string, body: Record<string, unknown>) =>
  callDaemon(layout.adminSocket(socket), '/v1/grant', body, Token)

beforeEach(async () => {
  // Short root: unix socket paths are limited to ~104 bytes.
  layout = layoutOf(mkdtempSync('/tmp/tvd-'))
  owner = (await initVault(layout.root, await machineFounder())).owner
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
  daemon = await startDaemon({ layout, env: { TYPEVAULT_DIR: layout.root }, keys: [owner] })
})

afterEach(async () => {
  await daemon.stop()
  rmSync(layout.root, { recursive: true, force: true })
})

describe('live grants', () => {
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
    const posted = await fetch(opened.url, {
      method: 'POST',
      body: new Uint8Array(body),
      headers: { 'content-type': 'application/octet-stream' },
    })
    expect(posted.status).toBe(204)
    const done = await access.call('/v1/request/wait', { id: opened.id }, z.object({ stored: z.string() }))
    expect(done.stored).toBe('resend')
    expect((await access.get(n('resend'))).fields).toEqual({ key: { type: 'secret' as const, value: 're_test_1' } })
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
  await fetch(opened.url, { method: 'POST', body, headers: { 'content-type': 'application/octet-stream' } })
  await expect(
    access.call('/v1/request/wait', { id: opened.id }, z.object({ stored: z.string() })),
  ).rejects.toMatchObject({
    code: 'tampered',
  })
  expect((await vault.find(n('openai')))?.payload.fields).toEqual({
    key: { type: 'secret' as const, value: 'sk-test-openai' },
  })
})

it('keeps sockets private to the owner', async () => {
  const { mode } = await Bun.file(join(layout.run, 'agent.sock')).stat()
  expect(mode & 0o777).toBe(0o600)
})

describe('unlocked session', () => {
  it('serves its grant from run/session.token and ends it with the daemon', async () => {
    // given a daemon started as an unlocked session
    await daemon.stop()
    const env = { TYPEVAULT_DIR: layout.root }
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
})

describe('daemon lock', () => {
  it('is held for the life of the daemon and released once it has stopped', async () => {
    expect(isLockHeld(layout.daemonLock)).toBe(true)

    await daemon.stop()

    expect(isLockHeld(layout.daemonLock)).toBe(false)
    daemon = await startDaemon({ layout, env: { TYPEVAULT_DIR: layout.root }, keys: [owner] })
  })

  it('keeps a new daemon from starting while another still holds it, shutting down', async () => {
    // given the running daemon stopped, and its lock still held as if its cleanup were unfinished
    await daemon.stop()
    const release = holdLock(layout.daemonLock)
    if (release === undefined) throw new Error('the lock was not free after stop')

    // then a new daemon refuses to start beside it
    const env = { TYPEVAULT_DIR: layout.root }
    await expect(startDaemon({ layout, env, keys: [owner] })).rejects.toMatchObject({ code: 'conflict' })
    release()
    daemon = await startDaemon({ layout, env, keys: [owner] })
  })
})
