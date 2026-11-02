import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { readAudit } from '../audit/log'
import { Admin } from '../core/admin'
import type { SecretKey } from '../core/crypto'
import { signerOf } from '../core/entries'
import { initVault } from '../core/init'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { envFor } from './env'
import { ScopedVault } from './scoped'
import { issueSealedGrant, readSealedGrant } from './sealed'
import { SealedAccess } from './sealed-access'

let root: string
let operator: SecretKey
let vault: Vault
const n = parseEntryName

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'typevault-access-'))
  operator = await initVault(root)
  vault = await Vault.open(root, [operator], {})
  const admin = new Admin(vault)
  await admin.addGroup('member')
  await admin.addGroup('trusted')
  await admin.include('trusted', 'member')
  const put = (name: string, group: string, fields: Record<string, string>) =>
    vault.put({ name: n(name), type: 'password', fields, group }, signerOf(operator))
  await put('github/bot', 'member', { username: 'bot', password: 'hunter2-bot' })
  await put('github/personal', 'member', { username: 'me', password: 'hunter2-me' })
  await put('stripe', 'trusted', { password: 'sk_live_x' })
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

describe('ScopedVault', () => {
  const member = () =>
    new ScopedVault(vault, [{ groups: ['member'], only: [] }], {
      mode: 'live',
      grant: 'g1',
      label: 'session:a',
      defaultGroup: 'member',
    })

  it('lists only entries the scope reaches', async () => {
    expect((await member().list()).map((entry): string => entry.name).sort()).toEqual(['github/bot', 'github/personal'])
  })

  it('narrows further along a derived chain', async () => {
    const derived = new ScopedVault(
      vault,
      [
        { groups: ['member'], only: [] },
        { groups: ['trusted'], only: ['github/bot'] },
      ],
      { mode: 'live' },
    )
    expect((await derived.list()).map((entry): string => entry.name)).toEqual(['github/bot'])
  })

  it('audits reads with the grant label and remembers values for redaction', async () => {
    const access = member()
    await access.get(n('github/bot'), 'login')
    expect(readAudit(vault.layout).at(-1)).toMatchObject({
      action: 'read',
      label: 'session:a',
      entries: ['github/bot'],
      reason: 'login',
    })
    expect(await access.readValues()).toEqual(['bot', 'hunter2-bot'])
  })

  it('refuses to overwrite a name held in a group the scope cannot reach', async () => {
    expect(member().set({ name: n('stripe'), type: 'api_key', fields: { key: 'x' } })).rejects.toMatchObject({
      code: 'denied',
    })
  })

  it('derives env names and loads TOTP codes instead of seeds', async () => {
    const env = envFor(
      [
        {
          ...(await member().get(n('github/bot'))),
          fields: { password: 'p4ss', totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' },
        },
      ],
      new Date(59_000),
    )
    expect(env).toEqual({ GITHUB_BOT_PASSWORD: 'p4ss', GITHUB_BOT_TOTP: '287082' })
  })
})

describe('sealed grants', () => {
  const issue = (ttlMs = 60_000) =>
    issueSealedGrant(vault, { groups: ['member'], only: ['github/*'], ttlMs, label: 'ci:deploy' })

  it('carries exactly the granted entries', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), root, {})
    expect((await access.values([])).map((value) => value.fields['password'])).toEqual(
      expect.arrayContaining(['hunter2-bot', 'hunter2-me']),
    )
    expect(await access.list()).toHaveLength(2)
  })

  it('writes entries that readers accept through the certificate', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), root, {})
    await access.set({ name: n('github/bot'), type: 'password', fields: { password: 'rotated' } })
    const stored = await (await Vault.open(root, [operator], {})).find(n('github/bot'))
    expect(stored?.payload.fields).toEqual({ password: 'rotated' })
    expect(stored?.envelope.signer.kind).toBe('cert')
  })

  it('cannot write outside its groups', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), root, {})
    expect(
      access.set({ name: n('github/x'), type: 'note', fields: { text: 'x' }, group: 'trusted' }),
    ).rejects.toMatchObject({ code: 'denied' })
  })

  it('refuses to work once expired', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue(-1)), root, {})
    expect(access.list()).rejects.toMatchObject({ code: 'expired' })
  })

  it('records the issue in the audit trail without values', async () => {
    await issue()
    const record = readAudit(vault.layout).at(-1)
    expect(record).toMatchObject({ action: 'grant.issue', mode: 'sealed', label: 'ci:deploy' })
    expect(JSON.stringify(record)).not.toContain('hunter2')
  })
})
