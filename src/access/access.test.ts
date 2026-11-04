import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { readAudit } from '../audit/log'
import { Admin } from '../core/admin'
import { adoptCertWrites } from '../core/adopt'
import type { SecretKey } from '../core/crypto'
import { signerAuthority, signerOf } from '../core/entries'
import { createIdentity } from '../core/identity'
import { type Founder, founderOf, initVault } from '../core/init'
import { layoutOf } from '../core/layout'
import { parseEntryName } from '../core/naming'
import { Vault } from '../core/vault'
import { envFor, explicitNames, resolveEnvRefs } from './env'
import { ScopedVault } from './scoped'
import { issueSealedGrant, readSealedGrant, sealedSigningSecret } from './sealed'
import { SealedAccess } from './sealed-access'

const machineFounder = async (): Promise<Founder> => founderOf((await createIdentity('owner', 'machine')).identity)

let root: string
let owner: SecretKey
let vault: Vault
const n = parseEntryName

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'typevault-access-'))
  owner = (await initVault(root, await machineFounder())).owner
  vault = await Vault.open(layoutOf(root), [owner], {})
  const admin = new Admin(vault)
  await admin.addTier('member')
  await admin.addTier('trusted')
  await admin.include('trusted', 'member')
  const put = (name: string, tier: string, fields: Record<string, string>) =>
    vault.put({ name: n(name), type: 'password', fields, tier }, signerOf(owner))
  await put('github/bot', 'member', { username: 'bot', password: 'hunter2-bot' })
  await put('github/personal', 'member', { username: 'me', password: 'hunter2-me' })
  await put('stripe', 'trusted', { password: 'sk_live_x' })
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

const own = { ownTiers: ['member'], explicit: [] }

describe('ScopedVault', () => {
  const member = () =>
    new ScopedVault(vault, [{ tiers: ['member'], only: [] }], {
      mode: 'live',
      grant: 'g1',
      label: 'session:a',
      defaultTier: 'member',
    })

  it('lists only entries the scope reaches', async () => {
    expect((await member().list()).map((entry): string => entry.name).sort()).toEqual(['github/bot', 'github/personal'])
  })

  it('hands out only the copy a duplicated name resolves to', async () => {
    await vault.put(
      { name: n('github/bot'), type: 'password', fields: { password: 'from-trusted' }, tier: 'trusted' },
      signerOf(owner),
    )
    const trusted = new ScopedVault(vault, [{ tiers: ['trusted'], only: [] }], { mode: 'live' })
    const values = await trusted.values(['github/bot'])
    expect(values.map((value) => value.fields['password'])).toEqual(['from-trusted'])
  })

  it('narrows further along a derived chain', async () => {
    const derived = new ScopedVault(
      vault,
      [
        { tiers: ['member'], only: [] },
        { tiers: ['trusted'], only: ['github/bot'] },
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

  it('writes to the only tier in reach when none is named', async () => {
    const access = new ScopedVault(vault, [{ tiers: ['member'], only: [] }], { mode: 'live' })
    const stored = await access.set({ name: n('openai'), type: 'api_key', fields: { key: 'sk-x' } })
    expect(stored.tier).toBe('member')
  })

  it('asks for a tier, listing the choices, when several are in reach', async () => {
    const direct = new ScopedVault(vault, [], { mode: 'direct' })
    const write = direct.set({ name: n('openai'), type: 'api_key', fields: { key: 'sk-x' } })
    await expect(write).rejects.toThrow('choose a tier with --tier (one of: member, trusted) or set TYPEVAULT_TIER')
  })

  it('rereads tiers before inferring one, so a tier added by another handle makes the choice ambiguous', async () => {
    const fresh = mkdtempSync(join(tmpdir(), 'typevault-access-stale-'))
    try {
      // given a client opened while `default` was the only tier
      const { owner: key } = await initVault(fresh, await machineFounder())
      const admin = new Admin(await Vault.open(layoutOf(fresh), [key], {}))
      await admin.addTier('default')
      const client = new ScopedVault(await Vault.open(layoutOf(fresh), [key], {}), [], { mode: 'direct' })

      // when another handle adds a second tier before the client writes
      await admin.addTier('other')
      const write = client.set({ name: n('openai'), type: 'api_key', fields: { key: 'sk-x' } })

      // then the client refuses to guess
      await expect(write).rejects.toThrow('one of: default, other')
    } finally {
      rmSync(fresh, { recursive: true, force: true })
    }
  })

  it('infers the only tier a direct key holder can open, ignoring tiers it cannot reach', async () => {
    const memberKey = await vault.keyring.unlock('member')
    if (memberKey === undefined) throw new Error('no member key')
    const direct = new ScopedVault(await Vault.open(layoutOf(root), [memberKey], {}), [], { mode: 'direct' })
    const stored = await direct.set({ name: n('openai'), type: 'api_key', fields: { key: 'sk-x' } })
    expect(stored.tier).toBe('member')
  })

  it('points to `tier add` when the vault has no tier yet', async () => {
    const fresh = mkdtempSync(join(tmpdir(), 'typevault-access-empty-'))
    try {
      const empty = await Vault.open(layoutOf(fresh), [(await initVault(fresh, await machineFounder())).owner], {})
      const write = new ScopedVault(empty, [], { mode: 'direct' }).set({
        name: n('openai'),
        type: 'api_key',
        fields: { key: 'sk-x' },
      })
      await expect(write).rejects.toThrow('create one with `typevault tier add <name>`')
    } finally {
      rmSync(fresh, { recursive: true, force: true })
    }
  })

  it('refuses to overwrite a name held in a tier the scope cannot reach', async () => {
    await expect(member().set({ name: n('stripe'), type: 'api_key', fields: { key: 'x' } })).rejects.toMatchObject({
      code: 'denied',
    })
  })

  it('never lets an entry set a loader variable such as PATH or LD_PRELOAD', async () => {
    const base = await member().get(n('github/bot'))
    const env = envFor(
      [
        { ...base, env: 'PATH', fields: { password: '/tmp/evil' } },
        { ...base, name: n('ld-preload'), type: 'note', fields: { text: 'x.so' } },
      ],
      new Date(0),
      own,
    )
    expect(env).toEqual({})
  })

  it('loads entries from included tiers only when named exactly', async () => {
    const base = await member().get(n('github/bot'))
    const lower = { ...base, name: n('planted'), tier: 'guest', fields: { password: 'x' } }
    expect(envFor([lower], new Date(0), own)).toEqual({})
    expect(envFor([lower], new Date(0), { ownTiers: ['member'], explicit: ['planted'] })).toEqual({
      PLANTED_PASSWORD: 'x',
    })
    expect(envFor([lower], new Date(0), { ownTiers: ['member'], explicit: explicitNames(['tv://Planted']) })).toEqual({
      PLANTED_PASSWORD: 'x',
    })
  })

  it('ignores the env override of an included-tier entry even when named', async () => {
    const base = await member().get(n('github/bot'))
    const lower = {
      ...base,
      name: n('openai'),
      type: 'api_key' as const,
      tier: 'guest',
      env: 'OPENAI_BASE_URL',
      fields: { key: 'https://evil' },
    }
    expect(envFor([lower], new Date(0), { ownTiers: ['member'], explicit: ['openai'] })).toEqual({
      OPENAI_KEY: 'https://evil',
    })
  })

  it('honors the env override of an included-tier entry written from above the reader', async () => {
    const base = await member().get(n('github/bot'))
    const imported = {
      ...base,
      name: n('openai'),
      type: 'api_key' as const,
      tier: 'guest',
      env: 'OPENAI_API_KEY',
      fields: { key: 'sk' },
      trustedWriter: true,
    }
    expect(envFor([imported], new Date(0), { ownTiers: ['member'], explicit: ['openai'] })).toEqual({
      OPENAI_API_KEY: 'sk',
    })
  })

  it('refuses two entries that set the same variable', async () => {
    const base = await member().get(n('github/bot'))
    const values = [
      { ...base, env: 'DATABASE_URL', fields: { password: 'a' } },
      { ...base, name: n('other'), env: 'DATABASE_URL', fields: { password: 'b' } },
    ]
    expect(() => envFor(values, new Date(0), own)).toThrow('both set DATABASE_URL')
  })

  it('refuses to store a reserved env override', async () => {
    await expect(
      member().set({ name: n('evil'), type: 'api_key', fields: { key: 'x' }, env: 'NODE_OPTIONS' }),
    ).rejects.toMatchObject({ code: 'invalid' })
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
      own,
    )
    expect(env).toEqual({ GITHUB_BOT_PASSWORD: 'p4ss', GITHUB_BOT_TOTP: '287082' })
  })

  it('derives env names for custom fields and skips one with no letter or digit left', async () => {
    const base = await member().get(n('github/bot'))
    const env = envFor([{ ...base, fields: { 'Recovery Code': 'r', 복구: 'k' } }], new Date(0), own)
    expect(env).toEqual({ GITHUB_BOT_RECOVERY_CODE: 'r' })
  })

  it('resolves a tv:// reference to a custom field, ignoring case when only one field matches', async () => {
    const base = await member().get(n('github/bot'))
    const get = async () => ({ ...base, fields: { ...base.fields, 'Recovery Code': 'r' } })
    const resolved = await resolveEnvRefs(
      {
        EXACT: 'tv://github/bot#Recovery Code',
        LOOSE: 'tv://github/bot#recovery code',
        OLD: 'tv://github/bot#PASSWORD',
      },
      get,
      new Date(0),
    )
    expect(resolved.env).toEqual({ EXACT: 'r', LOOSE: 'r', OLD: 'hunter2-bot' })
  })

  it('resolves tv:// references in env values and leaves other variables alone', async () => {
    const scope = member()
    const resolved = await resolveEnvRefs(
      {
        BOT_PASSWORD: 'tv://github/bot',
        BOT_USER: 'typevault://github/bot#username',
        ME: 'TV://GitHub/Personal#password',
        HOME_PAGE: 'https://example.com',
      },
      (name) => scope.get(name),
      new Date(0),
    )
    expect(resolved.env).toEqual({ BOT_PASSWORD: 'hunter2-bot', BOT_USER: 'bot', ME: 'hunter2-me' })
  })

  it('refuses a tv:// reference outside the scope, to a missing field or in a loader variable', async () => {
    const scope = member()
    const resolve = (env: Record<string, string>) => resolveEnvRefs(env, (name) => scope.get(name), new Date(0))
    await expect(resolve({ KEY: 'tv://stripe' })).rejects.toMatchObject({ code: 'not_found' })
    await expect(resolve({ KEY: 'tv://github/bot#url' })).rejects.toMatchObject({ code: 'not_found' })
    await expect(resolve({ NODE_OPTIONS: 'tv://github/bot' })).rejects.toMatchObject({ code: 'invalid' })
  })

  it.each(['http_proxy', 'https_proxy', 'npm_config_userconfig'])(
    'refuses a tv:// reference in lowercase %p before reading the entry',
    async (variable) => {
      const reads: string[] = []
      const get = async (name: string) => {
        reads.push(name)
        return member().get(n(name))
      }
      await expect(resolveEnvRefs({ [variable]: 'tv://github/bot' }, get, new Date(0))).rejects.toMatchObject({
        code: 'invalid',
      })
      expect(reads).toEqual([])
    },
  )
})

describe('OAuth refresh', () => {
  it('refreshes an expired token on read, stores it and audits the refresh', async () => {
    const server = Bun.serve({
      port: 0,
      hostname: '127.0.0.1',
      fetch: () => Response.json({ access_token: 'fresh-token', expires_in: 3600 }),
    })
    try {
      const fields = {
        access_token: 'stale-token',
        refresh_token: 'rt',
        expires_at: '2000-01-01T00:00:00.000Z',
        token_url: `http://127.0.0.1:${server.port}/token`,
      }
      await vault.put({ name: n('google'), type: 'oauth', fields, tier: 'member' }, signerOf(owner))
      const access = new ScopedVault(vault, [{ tiers: ['member'], only: [] }], { mode: 'live', label: 's' })
      expect((await access.get(n('google'))).fields['access_token']).toBe('fresh-token')
      expect((await vault.find(n('google')))?.payload.fields['access_token']).toBe('fresh-token')
      expect(readAudit(vault.layout).map((record) => record['action'])).toContain('refresh')
    } finally {
      await server.stop(true)
    }
  })
})

describe('sealed grants', () => {
  const issue = (ttlMs = 60_000) =>
    issueSealedGrant(vault, { tiers: ['member'], only: ['github/*'], ttlMs, label: 'ci:deploy' })

  it('carries exactly the granted entries', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    expect((await access.values([])).map((value) => value.fields['password'])).toEqual(
      expect.arrayContaining(['hunter2-bot', 'hunter2-me']),
    )
    expect(await access.list()).toHaveLength(2)
  })

  it('writes entries that readers accept through the certificate', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    await access.set({ name: n('github/bot'), type: 'password', fields: { password: 'rotated' } })
    const stored = await (await Vault.open(layoutOf(root), [owner], {})).find(n('github/bot'))
    expect(stored?.payload.fields).toEqual({ password: 'rotated' })
    expect(stored?.envelope.signer.kind).toBe('cert')
  })

  it('cannot write outside its tiers', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    await expect(
      access.set({ name: n('github/x'), type: 'note', fields: { text: 'x' }, tier: 'trusted' }),
    ).rejects.toMatchObject({ code: 'denied' })
  })

  it('refuses to work once expired', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue(-1)), layoutOf(root), {})
    await expect(access.list()).rejects.toMatchObject({ code: 'expired' })
  })

  const certSigner = async (ttlMs: number) => {
    const bundle = await readSealedGrant(await issue(ttlMs))
    return { ref: { kind: 'cert' as const, cert: bundle.write.cert }, signSecret: sealedSigningSecret(bundle) }
  }

  it('rejects a certificate write outside its --only, whatever the holder signs', async () => {
    await vault.put(
      { name: n('aws/root'), type: 'api_key', fields: { key: 'forged' }, tier: 'member' },
      await certSigner(60_000),
    )
    expect(await vault.find(n('aws/root'))).toBeUndefined()
    expect((await vault.scan()).problems.map((p) => p.reason)).toContain(
      "aws/root is outside the writing grant's --only",
    )
  })

  it('stops honoring a certificate once the reader clock passes its expiry', async () => {
    await expect(
      vault.put({ name: n('github/x'), type: 'note', fields: { text: 'late' }, tier: 'member' }, await certSigner(-1)),
    ).rejects.toMatchObject({ code: 'denied' })
  })

  it('honors an expired certificate only when the owner explicitly adopts', async () => {
    const { ref } = await certSigner(-1)
    const at = new Date(Date.parse(ref.cert.exp) - 1_000).toISOString()
    expect(signerAuthority(ref, 'member', vault.state, at)).toBeUndefined()
    expect(signerAuthority(ref, 'member', vault.state, at, null)).toBe(ref.cert.signPublic)
  })

  it('adopts certificate writes so they outlive the certificate', async () => {
    await vault.put(
      { name: n('github/new'), type: 'note', fields: { text: 'hi' }, tier: 'member' },
      await certSigner(60_000),
    )
    expect(await adoptCertWrites(vault)).toEqual(['github/new'])
    expect((await vault.find(n('github/new')))?.envelope.signer.kind).toBe('tier')
  })

  it('records the issue in the audit trail without values', async () => {
    await issue()
    const record = readAudit(vault.layout).at(-1)
    expect(record).toMatchObject({ action: 'grant.issue', mode: 'sealed', label: 'ci:deploy' })
    expect(JSON.stringify(record)).not.toContain('hunter2')
  })
})
