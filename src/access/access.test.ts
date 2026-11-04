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
import { parseEntryName, type Field } from '../core/naming'
import { Vault } from '../core/vault'
import { envFor, explicitNames, resolveEnvRefs } from './env'
import { ScopedVault } from './scoped'
import { issueSealedGrant, readSealedGrant, type SealedBundle, sealedSigningSecret } from './sealed'
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
  const put = (name: string, tier: string, fields: Record<string, Field>) =>
    vault.put({ name: n(name), fields, tier }, signerOf(owner))
  await put('github/bot', 'member', {
    username: { type: 'text', value: 'bot' },
    password: { type: 'secret', value: 'hunter2-bot' },
  })
  await put('github/personal', 'member', {
    username: { type: 'text', value: 'me' },
    password: { type: 'secret', value: 'hunter2-me' },
  })
  await put('stripe', 'trusted', { password: { type: 'secret', value: 'sk_live_x' } })
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
      {
        name: n('github/bot'),
        fields: { password: { type: 'secret' as const, value: 'from-trusted' } },
        tier: 'trusted',
      },
      signerOf(owner),
    )
    const trusted = new ScopedVault(vault, [{ tiers: ['trusted'], only: [] }], { mode: 'live' })
    const values = await trusted.values(['github/bot'])
    expect(values.map((value) => value.fields['password']?.value)).toEqual(['from-trusted'])
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
    const stored = await access.set({ name: n('openai'), fields: { key: { type: 'secret' as const, value: 'sk-x' } } })
    expect(stored.tier).toBe('member')
  })

  it('asks for a tier, listing the choices, when several are in reach', async () => {
    const direct = new ScopedVault(vault, [], { mode: 'direct' })
    const write = direct.set({ name: n('openai'), fields: { key: { type: 'secret' as const, value: 'sk-x' } } })
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
      const write = client.set({ name: n('openai'), fields: { key: { type: 'secret' as const, value: 'sk-x' } } })

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
    const stored = await direct.set({ name: n('openai'), fields: { key: { type: 'secret' as const, value: 'sk-x' } } })
    expect(stored.tier).toBe('member')
  })

  it('points to `tier add` when the vault has no tier yet', async () => {
    const fresh = mkdtempSync(join(tmpdir(), 'typevault-access-empty-'))
    try {
      const empty = await Vault.open(layoutOf(fresh), [(await initVault(fresh, await machineFounder())).owner], {})
      const write = new ScopedVault(empty, [], { mode: 'direct' }).set({
        name: n('openai'),

        fields: { key: { type: 'secret' as const, value: 'sk-x' } },
      })
      await expect(write).rejects.toThrow('create one with `typevault tier add <name>`')
    } finally {
      rmSync(fresh, { recursive: true, force: true })
    }
  })

  it('refuses to overwrite a name held in a tier the scope cannot reach', async () => {
    await expect(
      member().set({ name: n('stripe'), fields: { key: { type: 'secret' as const, value: 'x' } } }),
    ).rejects.toMatchObject({
      code: 'denied',
    })
  })

  it('uses the entry name for $default and applies its trusted env override', async () => {
    const base = await member().get(n('github/bot'))
    const value = {
      ...base,
      fields: {
        $default: { type: 'secret' as const, value: 'default-secret' },
        label: { type: 'text' as const, value: 'public' },
      },
    }
    expect(envFor([value], new Date(0), own)).toEqual({ GITHUB_BOT: 'default-secret', GITHUB_BOT_LABEL: 'public' })
    expect(envFor([{ ...value, env: 'CUSTOM_TOKEN' }], new Date(0), own)).toEqual({
      CUSTOM_TOKEN: 'default-secret',
      GITHUB_BOT_LABEL: 'public',
    })
  })

  it('derives every name for an entry with several fields and no default even when it carries --env', async () => {
    const base = await member().get(n('github/bot'))
    expect(envFor([{ ...base, env: 'CUSTOM_TOKEN' }], new Date(0), own)).toEqual({
      GITHUB_BOT_USERNAME: 'bot',
      GITHUB_BOT_PASSWORD: 'hunter2-bot',
    })
  })

  it('never lets an entry set a loader variable such as PATH or LD_PRELOAD', async () => {
    const base = await member().get(n('github/bot'))
    const env = envFor(
      [
        { ...base, env: 'PATH', fields: { password: { type: 'secret' as const, value: '/tmp/evil' } } },
        { ...base, name: n('ld-preload'), fields: { text: { type: 'secret' as const, value: 'x.so' } } },
      ],
      new Date(0),
      own,
    )
    expect(env).toEqual({})
  })

  it('loads entries from included tiers only when named exactly', async () => {
    const base = await member().get(n('github/bot'))
    const lower = {
      ...base,
      name: n('planted'),
      tier: 'guest',
      fields: { password: { type: 'secret' as const, value: 'x' } },
    }
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
      fields: {
        key: { type: 'secret' as const, value: 'https://evil' },
        label: { type: 'text' as const, value: 'lower-label' },
      },
    }
    expect(envFor([lower], new Date(0), { ownTiers: ['member'], explicit: ['openai'] })).toEqual({
      OPENAI_KEY: 'https://evil',
      OPENAI_LABEL: 'lower-label',
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
      fields: { key: { type: 'secret' as const, value: 'sk' } },
      trustedWriter: true,
    }
    expect(envFor([imported], new Date(0), { ownTiers: ['member'], explicit: ['openai'] })).toEqual({
      OPENAI_API_KEY: 'sk',
    })
  })

  it('refuses two entries that set the same variable', async () => {
    const base = await member().get(n('github/bot'))
    const values = [
      { ...base, env: 'DATABASE_URL', fields: { password: { type: 'secret' as const, value: 'a' } } },
      { ...base, name: n('other'), env: 'DATABASE_URL', fields: { password: { type: 'secret' as const, value: 'b' } } },
    ]
    expect(() => envFor(values, new Date(0), own)).toThrow('both set DATABASE_URL')
  })

  it('refuses to store a reserved env override', async () => {
    await expect(
      member().set({ name: n('evil'), fields: { key: { type: 'secret' as const, value: 'x' } }, env: 'NODE_OPTIONS' }),
    ).rejects.toMatchObject({ code: 'invalid' })
  })

  it('derives env names and loads TOTP codes instead of seeds', async () => {
    const env = envFor(
      [
        {
          ...(await member().get(n('github/bot'))),
          fields: {
            password: { type: 'secret' as const, value: 'p4ss' },
            authenticator: { type: 'totp' as const, value: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' },
          },
        },
      ],
      new Date(59_000),
      own,
    )
    expect(env).toEqual({ GITHUB_BOT_PASSWORD: 'p4ss', GITHUB_BOT_AUTHENTICATOR: '287082' })
  })

  it('derives env names for custom fields and skips one with no letter or digit left', async () => {
    const base = await member().get(n('github/bot'))
    const env = envFor(
      [
        {
          ...base,
          fields: {
            'Recovery Code': { type: 'secret' as const, value: 'r' },
            복구: { type: 'secret' as const, value: 'k' },
          },
        },
      ],
      new Date(0),
      own,
    )
    expect(env).toEqual({ GITHUB_BOT_RECOVERY_CODE: 'r' })
  })

  it('resolves a tv:// reference to a custom field, ignoring case when only one field matches', async () => {
    const base = await member().get(n('github/bot'))
    const get = async () => ({
      ...base,
      fields: { ...base.fields, 'Recovery Code': { type: 'secret' as const, value: 'r' } },
    })
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
        BOT_PASSWORD: 'tv://github/bot#password',
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
      await vault.put(
        {
          name: n('google'),
          fields: {
            session: { type: 'oauth', value: fields },
            alternate: { type: 'oauth', value: { ...fields, access_token: 'other-stale' } },
            description: { type: 'text', value: 'public description' },
          },
          tier: 'member',
        },
        signerOf(owner),
      )
      const access = new ScopedVault(vault, [{ tiers: ['member'], only: [] }], { mode: 'live', label: 's' })
      expect((await access.get(n('google'))).fields['session']?.value).toMatchObject({ access_token: 'fresh-token' })
      expect((await vault.find(n('google')))?.payload.fields['session']?.value).toMatchObject({
        access_token: 'fresh-token',
      })
      expect((await vault.find(n('google')))?.payload.fields['alternate']?.value).toMatchObject({
        access_token: 'fresh-token',
      })
      expect(await access.readValues()).toEqual(
        expect.arrayContaining(['fresh-token', 'rt', fields.token_url, 'public description']),
      )
      expect(readAudit(vault.layout).map((record) => record['action'])).toContain('refresh')
    } finally {
      await server.stop(true)
    }
  })
})

describe('OAuth refresh failures', () => {
  it('keeps a rotated token when a later field fails to refresh', async () => {
    const server = Bun.serve({
      port: 0,
      hostname: '127.0.0.1',
      fetch: async (request) =>
        new URLSearchParams(await request.text()).get('refresh_token') === 'rt-session'
          ? Response.json({ access_token: 'fresh-session', refresh_token: 'rt-session-2', expires_in: 3600 })
          : new Response('revoked', { status: 400 }),
    })
    try {
      const expired = { expires_at: '2000-01-01T00:00:00.000Z', token_url: `http://127.0.0.1:${server.port}/token` }
      await vault.put(
        {
          name: n('google'),
          fields: {
            session: { type: 'oauth', value: { ...expired, access_token: 'stale', refresh_token: 'rt-session' } },
            alternate: { type: 'oauth', value: { ...expired, access_token: 'stale', refresh_token: 'rt-revoked' } },
          },
          tier: 'member',
        },
        signerOf(owner),
      )
      const access = new ScopedVault(vault, [{ tiers: ['member'], only: [] }], { mode: 'live', label: 's' })

      await expect(access.get(n('google'))).rejects.toMatchObject({ code: 'unavailable' })

      expect((await vault.find(n('google')))?.payload.fields['session']?.value).toMatchObject({
        access_token: 'fresh-session',
        refresh_token: 'rt-session-2',
      })
    } finally {
      await server.stop(true)
    }
  })
})

describe('sealed grants', () => {
  it('flattens every compound string for redaction, including text values', async () => {
    await vault.put(
      {
        name: n('github/bot'),
        tier: 'member',
        fields: {
          session: {
            type: 'oauth',
            value: { access_token: 'access', refresh_token: 'refresh', client_secret: 'client' },
          },
          description: { type: 'text', value: 'public description' },
          empty: { type: 'secret', value: '' },
        },
      },
      signerOf(owner),
    )
    const access = new SealedAccess(await readSealedGrant(await issue()), undefined, {})
    expect(await access.readValues()).toEqual(
      expect.arrayContaining(['access', 'refresh', 'client', 'public description']),
    )
    expect(await access.readValues()).not.toContain('')
  })

  const issue = (ttlMs = 60_000) =>
    issueSealedGrant(vault, { tiers: ['member'], only: ['github/*'], ttlMs, label: 'ci:deploy' })

  it('carries exactly the granted entries', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    expect((await access.values([])).map((value) => value.fields['password']?.value)).toEqual(
      expect.arrayContaining(['hunter2-bot', 'hunter2-me']),
    )
    expect(await access.list()).toHaveLength(2)
  })

  it('writes entries that readers accept through the certificate', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    await access.set({ name: n('github/bot'), fields: { password: { type: 'secret' as const, value: 'rotated' } } })
    const stored = await (await Vault.open(layoutOf(root), [owner], {})).find(n('github/bot'))
    expect(stored?.payload.fields).toEqual({ password: { type: 'secret' as const, value: 'rotated' } })
    expect(stored?.envelope.signer.kind).toBe('cert')
  })

  it('cannot write outside its tiers', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    await expect(
      access.set({ name: n('github/x'), fields: { text: { type: 'secret' as const, value: 'x' } }, tier: 'trusted' }),
    ).rejects.toMatchObject({ code: 'denied' })
  })

  it('refuses to work once expired', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue(-1)), layoutOf(root), {})
    await expect(access.list()).rejects.toMatchObject({ code: 'expired' })
  })

  it('removes an entry the certificate covers', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    await access.remove(n('github/bot'))
    expect(await vault.find(n('github/bot'))).toBeUndefined()
  })

  it('removes an entry its own certificate rewrote after the grant was issued', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    await access.set({ name: n('github/bot'), fields: { password: { type: 'secret' as const, value: 'rotated' } } })
    await access.remove(n('github/bot'))
    expect(await vault.find(n('github/bot'))).toBeUndefined()
  })

  // The holder can decrypt and re-seal its own bundle, so only the issuer-signed certificate is trusted.
  const forgeRemoval = async (target: string, bundle: SealedBundle) => {
    const stored = await vault.find(n(target))
    if (stored === undefined) throw new Error(`missing ${target}`)
    const { id, tier, rev } = stored.envelope
    const forged = {
      ...bundle,
      exp: new Date(Date.now() + 60_000).toISOString(),
      scope: { tiers: ['trusted'], only: [] },
      entries: [{ ...bundle.entries[0]!, name: n(target), id, tier, rev }],
    }
    return new SealedAccess(forged, layoutOf(root), {}).remove(n(target))
  }

  it('refuses to remove an entry outside its certificate tiers, whatever the bundle claims', async () => {
    await expect(forgeRemoval('stripe', await readSealedGrant(await issue()))).rejects.toMatchObject({ code: 'denied' })
    expect(await vault.find(n('stripe'))).toBeDefined()
  })

  it('refuses to remove an entry outside its certificate --only, whatever the bundle claims', async () => {
    await vault.put(
      { name: n('aws/root'), fields: { key: { type: 'secret', value: 'k' } }, tier: 'member' },
      signerOf(owner),
    )
    await expect(forgeRemoval('aws/root', await readSealedGrant(await issue()))).rejects.toMatchObject({
      code: 'denied',
    })
    expect(await vault.find(n('aws/root'))).toBeDefined()
  })

  it('refuses to remove once its certificate expires, whatever the bundle claims', async () => {
    await expect(forgeRemoval('github/bot', await readSealedGrant(await issue(-1)))).rejects.toMatchObject({
      code: 'denied',
    })
    expect(await vault.find(n('github/bot'))).toBeDefined()
  })

  it('refuses to remove an entry renamed out of its --only since the grant was issued', async () => {
    const access = new SealedAccess(await readSealedGrant(await issue()), layoutOf(root), {})
    await vault.move(n('github/bot'), n('aws/bot'), signerOf(owner))
    await expect(access.remove(n('github/bot'))).rejects.toMatchObject({ code: 'denied' })
    expect(await vault.find(n('aws/bot'))).toBeDefined()
  })

  const certSigner = async (ttlMs: number) => {
    const bundle = await readSealedGrant(await issue(ttlMs))
    return { ref: { kind: 'cert' as const, cert: bundle.write.cert }, signSecret: sealedSigningSecret(bundle) }
  }

  it('rejects a certificate write outside its --only, whatever the holder signs', async () => {
    await vault.put(
      { name: n('aws/root'), fields: { key: { type: 'secret' as const, value: 'forged' } }, tier: 'member' },
      await certSigner(60_000),
    )
    expect(await vault.find(n('aws/root'))).toBeUndefined()
    expect((await vault.scan()).problems.map((p) => p.reason)).toContain(
      "aws/root is outside the writing grant's --only",
    )
  })

  it('stops honoring a certificate once the reader clock passes its expiry', async () => {
    await expect(
      vault.put(
        { name: n('github/x'), fields: { text: { type: 'secret' as const, value: 'late' } }, tier: 'member' },
        await certSigner(-1),
      ),
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
      { name: n('github/new'), fields: { text: { type: 'secret' as const, value: 'hi' } }, tier: 'member' },
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
