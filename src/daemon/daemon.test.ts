import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { readAudit } from '../audit/log'
import { Admin } from '../core/admin'
import { seal, type SecretKey } from '../core/crypto'
import { utf8 } from '../core/encoding'
import { signerOf } from '../core/entries'
import { initVault } from '../core/init'
import { type Layout, layoutOf } from '../core/layout'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { callDaemon } from './client'
import { type RunningDaemon, startDaemon } from './daemon'
import { LiveAccess } from './live-access'

let layout: Layout
let operator: SecretKey
let daemon: RunningDaemon
const n = parseEntryName
const Token = z.object({ token: z.string() })

const grant = (socket: string, body: Record<string, unknown>) =>
  callDaemon(layout.adminSocket(socket), '/v1/grant', body, Token)

beforeEach(async () => {
  // Short root: unix socket paths are limited to ~104 bytes.
  layout = layoutOf(mkdtempSync('/tmp/tvd-'))
  operator = await initVault(layout.root)
  const vault = await Vault.open(layout.root, [operator], {})
  const admin = new Admin(vault)
  await admin.addGroup('member')
  await admin.addGroup('trusted')
  await admin.include('trusted', 'member')
  await admin.setCeiling('bot', 'member')
  await vault.put(
    { name: n('github/bot'), type: 'password', fields: { password: 'hunter2-bot' }, group: 'member' },
    signerOf(operator),
  )
  await vault.put(
    { name: n('openai'), type: 'api_key', fields: { key: 'sk-test-openai' }, group: 'member' },
    signerOf(operator),
  )
  await vault.put(
    { name: n('stripe'), type: 'api_key', fields: { key: 'sk_live_x' }, group: 'trusted' },
    signerOf(operator),
  )
  daemon = await startDaemon({ root: layout.root, env: { TYPEVAULT_DIR: layout.root } })
})

afterEach(async () => {
  await daemon.stop()
  rmSync(layout.root, { recursive: true, force: true })
})

describe('live grants', () => {
  it('serves values within the grant and audits each read with its label', async () => {
    const { token } = await grant('default', { groups: ['member'], label: 'session:abc' })
    const access = new LiveAccess(layout.agentSocket, token)
    expect((await access.list()).map((e): string => e.name).sort()).toEqual(['github/bot', 'openai'])
    expect((await access.get(n('openai'))).fields).toEqual({ key: 'sk-test-openai' })
    expect(readAudit(layout).at(-1)).toMatchObject({
      action: 'read',
      mode: 'live',
      label: 'session:abc',
      entries: ['openai'],
    })
  })

  it('refuses a grant above the socket ceiling', async () => {
    await expect(grant('bot', { groups: ['trusted'] })).rejects.toMatchObject({ code: 'denied' })
  })

  it('narrows a derived grant and revokes it with its parent', async () => {
    const { token } = await grant('default', { groups: ['member'], label: 'agent:a' })
    const parent = new LiveAccess(layout.agentSocket, token)
    const derived = await parent.call('/v1/derive', { only: ['github/*'] }, Token)
    const child = new LiveAccess(layout.agentSocket, derived.token)
    expect((await child.list()).map((e): string => e.name)).toEqual(['github/bot'])
    await callDaemon(layout.adminSocket('default'), '/v1/revoke', { label: 'agent:a' }, z.json())
    await expect(child.list()).rejects.toMatchObject({ code: 'denied' })
  })

  it('rejects an unknown token', async () => {
    await expect(new LiveAccess(layout.agentSocket, 'tvl1.nope.nope').list()).rejects.toMatchObject({ code: 'denied' })
  })

  it('remembers what a grant read, for redaction', async () => {
    const { token } = await grant('default', { groups: ['member'] })
    const access = new LiveAccess(layout.agentSocket, token)
    await access.get(n('github/bot'))
    expect(await access.readValues()).toEqual(['hunter2-bot'])
  })
})

describe('secret prompt', () => {
  it('stores what the page submits, encrypted to the group, without the daemon seeing plaintext', async () => {
    const { token } = await grant('default', { groups: ['member'], label: 'session:p' })
    const access = new LiveAccess(layout.agentSocket, token)
    const opened = await access.call(
      '/v1/request',
      { name: 'resend', type: 'api_key', reason: 'send mail' },
      z.object({ id: z.string(), url: z.string(), code: z.string() }),
    )
    const vault = await Vault.open(layout.root, [operator], {})
    const recipients = [vault.state.groups['member']?.recipient ?? '', vault.state.operator.recipient]
    const now = new Date().toISOString()
    const payload = {
      v: 1,
      name: 'resend',
      type: 'api_key',
      fields: { key: 're_test_1' },
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
    expect((await access.get(n('resend'))).fields).toEqual({ key: 're_test_1' })
  })
})

it('refuses a prompt submission for a different entry than the one requested', async () => {
  const { token } = await grant('default', { groups: ['member'], only: ['resend'] })
  const access = new LiveAccess(layout.agentSocket, token)
  const opened = await access.call(
    '/v1/request',
    { name: 'resend', type: 'api_key', reason: 'mail' },
    z.object({ id: z.string(), url: z.string(), code: z.string() }),
  )
  const vault = await Vault.open(layout.root, [operator], {})
  const recipients = [vault.state.groups['member']?.recipient ?? '', vault.state.operator.recipient]
  const now = new Date().toISOString()
  const forged = {
    v: 1,
    name: 'openai',
    type: 'api_key',
    fields: { key: 'forged' },
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
  expect((await vault.find(n('openai')))?.payload.fields).toEqual({ key: 'sk-test-openai' })
})

it('keeps sockets private to the owner', async () => {
  const { mode } = await Bun.file(join(layout.run, 'agent.sock')).stat()
  expect(mode & 0o777).toBe(0o600)
})
