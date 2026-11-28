import { afterEach, beforeEach, expect, it, setDefaultTimeout } from 'bun:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { issueSealedGrant } from '../../access/sealed'
import { Admin } from '../../core/admin'
import { seal } from '../../core/crypto'
import { utf8 } from '../../core/encoding'
import { signCiphertext, signerOf } from '../../core/entries'
import { createIdentity } from '../../core/identity'
import { founderOf, initGlobalVault } from '../../core/init'
import { globalLayout } from '../../core/layout'
import { parseEntryName } from '../../core/naming'
import { generatePasskeyKey } from '../../core/passkey.harness'
import type { EntryPayload } from '../../core/payload'
import { Vault } from '../../core/vault'

const CLI = join(import.meta.dir, '..', 'index.ts')
// Each test sets up a vault and starts real CLI processes, which a parallel run on a busy machine can stretch past the
// 5s default: the same bound the CLI scenario tests use.
setDefaultTimeout(30_000)
let root: string

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'typevault-run-'))
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

it.each([
  ['owner', 'CURL_HOME'],
  ['member', 'CURL_HOME'],
  ['owner', 'SERVICE_PROXY'],
  ['member', 'SERVICE_PROXY'],
] as const)('reads a stored %s-signed %s override but never injects it', async (writer, variable) => {
  const env = { HOME: root, XDG_CONFIG_HOME: root, TYPEVAULT_DIR: join(root, 'vault') }
  const { identity } = await createIdentity('owner', 'machine')
  const { owner } = await initGlobalVault(founderOf(identity), env)
  const vault = await Vault.open(globalLayout(env), [owner], env)
  const admin = new Admin(vault)
  await admin.addTier('member')
  await admin.addTier('trusted')
  await admin.include('trusted', 'member')
  const key = writer === 'owner' ? owner : await vault.keyring.unlock('member')
  const tier = vault.state.tiers['member']
  if (key === undefined || tier === undefined) throw new Error('missing member tier')
  const at = new Date().toISOString()
  const payload: EntryPayload = {
    v: 1,
    name: parseEntryName(variable.toLowerCase().replaceAll('_', '-')),
    fields: { $default: { type: 'secret', value: 'dummy-secret' } },
    env: variable,
    tags: [],
    created: at,
    rotated: at,
  }
  // A valid signature does not imply that the writer followed today's environment policy.
  const ciphertext = await seal([tier.recipient, vault.state.owner.recipient], utf8(JSON.stringify(payload)))
  const envelope = signCiphertext(
    { id: `member.${'a'.repeat(32)}`, tier: 'member', rev: 1, at },
    ciphertext,
    vault.state,
    signerOf(key),
  )
  writeFileSync(join(vault.layout.entries, `${envelope.id}.json`), JSON.stringify(envelope))
  const grant = await issueSealedGrant(vault, { tiers: ['trusted'], only: [], ttlMs: 60_000, label: 'test' })
  const cli = async (args: readonly string[]) => {
    const child = Bun.spawn([process.execPath, CLI, ...args], {
      cwd: root,
      env: { ...env, TYPEVAULT_GRANT: grant },
      stdin: 'ignore',
      stdout: 'pipe',
      stderr: 'pipe',
      timeout: 10_000,
    })
    const [code, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ])
    return { code, stdout, stderr }
  }

  expect(await cli(['get', payload.name, '--reveal'])).toMatchObject({ code: 0, stdout: 'dummy-secret\n' })
  expect(
    await cli([
      'run',
      '--only',
      payload.name,
      '--',
      process.execPath,
      '-e',
      'console.log(Object.hasOwn(process.env, process.argv[1]))',
      variable,
    ]),
  ).toMatchObject({ code: 0, stdout: 'false\n' })
})

it("leaves a passkey out of the child's automatic variables, and hands it over when a reference names it", async () => {
  // given an entry holding a passkey beside a text field, read through a sealed grant
  const env = { HOME: root, XDG_CONFIG_HOME: root, TYPEVAULT_DIR: join(root, 'vault') }
  const { identity } = await createIdentity('owner', 'machine')
  const { owner } = await initGlobalVault(founderOf(identity), env)
  const vault = await Vault.open(globalLayout(env), [owner], env)
  await new Admin(vault).addTier('member')
  const privateKey = await generatePasskeyKey()
  const passkey = { rp_id: 'example.com', credential_id: 'Y3JlZA', private_key: privateKey, discoverable: false }
  await vault.put(
    {
      name: parseEntryName('site'),
      tier: 'member',
      fields: { passkey: { type: 'passkey', value: passkey }, username: { type: 'text', value: 'bob' } },
    },
    signerOf(owner),
  )
  const grant = await issueSealedGrant(vault, { tiers: ['member'], only: [], ttlMs: 60_000, label: 'test' })
  // The child reports only whether each variable matches, never its value.
  const run = async (extra: Record<string, string>) => {
    const child = Bun.spawn(
      [
        process.execPath,
        CLI,
        'run',
        '--only',
        'site',
        '--',
        process.execPath,
        '-e',
        "const e = process.env; console.log([e.SITE_USERNAME === 'bob', Object.hasOwn(e, 'SITE_PASSKEY') && JSON.parse(e.SITE_PASSKEY).private_key === e.EXPECTED_KEY].join(' '))",
      ],
      {
        cwd: root,
        env: { ...env, TYPEVAULT_GRANT: grant, EXPECTED_KEY: privateKey, ...extra },
        stdin: 'ignore',
        stdout: 'pipe',
        stderr: 'pipe',
        timeout: 10_000,
      },
    )
    const [code, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()])
    return { code, stdout }
  }

  // then automatic loading delivers the text field but not the passkey
  expect(await run({})).toEqual({ code: 0, stdout: 'true false\n' })
  // and a reference under the old variable name still hands the program the credential
  expect(await run({ SITE_PASSKEY: 'typevault://site#passkey' })).toEqual({ code: 0, stdout: 'true true\n' })
})
