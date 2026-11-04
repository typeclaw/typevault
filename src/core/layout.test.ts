import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { machineKeys } from '../access/keys'
import { anchorAudit, appendAudit, verifyAudit } from '../audit/log'
import { callDaemon } from '../daemon/client'
import { startDaemon } from '../daemon/daemon'
import { LiveAccess } from '../daemon/live-access'
import { Admin } from './admin'
import { encodeSecretKey, type SecretKey } from './crypto'
import { signerOf } from './entries'
import { createIdentity } from './identity'
import { type Founder, founderOf, initLocalVault } from './init'
import { type Layout, localLayout } from './layout'
import { parseEntryName } from './naming'
import { Vault } from './vault'

let base: string
let env: Record<string, string>

beforeEach(() => {
  // Short root: unix socket paths are limited to ~104 bytes.
  base = mkdtempSync('/tmp/tvl-')
  env = { XDG_CONFIG_HOME: join(base, 'c') }
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

const machineFounder = async (): Promise<Founder> => founderOf((await createIdentity('owner', 'machine')).identity)

it('rejects a project vault whose owner was replaced, even with a key from the environment', async () => {
  // given a project vault this checkout trusts, and a member's key in TYPEVAULT_KEY
  const member = await createIdentity('owner', 'machine')
  const project = (await initLocalVault(join(base, 'project', '.typevault'), founderOf(member.identity), env)).layout
  const keyEnv = { ...env, TYPEVAULT_KEY: encodeSecretKey(member.key) }

  // when the owner and its signed manifests are replaced by another vault's
  const other = (await initLocalVault(join(base, 'other', '.typevault'), await machineFounder(), env)).layout
  for (const file of ['owner.json', 'tiers.json', 'members.json', 'signers.json', 'ceilings.json']) {
    copyFileSync(join(other.vault, file), join(project.vault, file))
  }
  const layout = localLayout(project.vault, keyEnv)

  // then opening it is refused instead of trusting the new owner
  await expect(Vault.open(layout, machineKeys(keyEnv), keyEnv)).rejects.toMatchObject({ code: 'tampered' })
})

describe('two clones of one project vault', () => {
  let first: Layout
  let second: Layout
  let owner: SecretKey

  beforeEach(async () => {
    ;({ layout: first, owner } = await initLocalVault(join(base, 'a', '.typevault'), await machineFounder(), env))
    await new Admin(await Vault.open(first, [owner], env)).addTier('member')
    cpSync(first.vault, join(base, 'b', '.typevault'), { recursive: true })
    second = localLayout(join(base, 'b', '.typevault'), env)
  })

  it('share keys but each run a daemon over their own files', async () => {
    // given each clone holding a different entry
    for (const [layout, name] of [
      [first, 'alpha'],
      [second, 'beta'],
    ] as const) {
      const vault = await Vault.open(layout, [owner], env)
      await vault.put(
        { name: parseEntryName(name), type: 'note', fields: { text: name }, tier: 'member' },
        signerOf(owner),
      )
    }

    // when both daemons run at once
    const daemons = await Promise.all([first, second].map((layout) => startDaemon({ layout, env, keys: [owner] })))
    try {
      const names = await Promise.all(
        [first, second].map(async (layout) => {
          const Issued = z.object({ token: z.string() })
          const { token } = await callDaemon(layout.adminSocket('default'), '/v1/grant', { tiers: ['member'] }, Issued)
          return (await new LiveAccess(layout.agentSocket, token).list()).map((entry): string => entry.name)
        }),
      )

      // then each serves only its own clone
      expect(names).toEqual([['alpha'], ['beta']])
    } finally {
      await Promise.all(daemons.map((daemon) => daemon.stop()))
    }
  })

  it('recover an interrupted transaction only in the clone that started it', async () => {
    // given a committed but unapplied transaction in the first clone
    const staged = join(first.txnDir, 'interrupted')
    mkdirSync(join(staged, 'files'), { recursive: true })
    writeFileSync(join(staged, 'files', '0'), 'from a')
    writeFileSync(join(staged, 'manifest.json'), JSON.stringify({ puts: ['marker.txt'], removes: [] }))
    writeFileSync(join(staged, 'COMMITTED'), '')

    // when the second clone opens, it leaves it alone
    await Vault.open(second, [], env)
    expect(existsSync(join(second.vault, 'marker.txt'))).toBe(false)
    expect(existsSync(staged)).toBe(true)

    // then the first clone rolls it forward into its own vault
    await Vault.open(first, [], env)
    expect(readFileSync(join(first.vault, 'marker.txt'), 'utf8')).toBe('from a')
  })

  it('verify their own audit chains against anchors pulled from each other', async () => {
    // given each clone anchoring its own log, and the first clone's anchors pulled into the second
    for (const layout of [first, second]) {
      await appendAudit(layout, { action: 'read', mode: 'direct', entries: [layout.vault] })
      await anchorAudit(layout)
    }
    cpSync(join(first.vault, 'audit-anchors'), join(second.vault, 'audit-anchors'), { recursive: true })

    // then both verify, and a rewritten first log still fails against its own anchor
    expect(verifyAudit(second)).toEqual({ ok: true, records: 1 })
    expect(verifyAudit(first)).toEqual({ ok: true, records: 1 })
    rmSync(first.auditLog)
    await appendAudit(first, { action: 'read', mode: 'direct', entries: ['forged'] })
    expect(verifyAudit(first)).toEqual({ ok: false, reason: 'local log no longer matches the anchor at record 1' })
  })
})
