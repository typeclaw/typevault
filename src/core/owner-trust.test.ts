import { afterEach, beforeEach, expect, it } from 'bun:test'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { anchorAudit, appendAudit, verifyAudit } from '../audit/log'
import { Admin } from './admin'
import { generateSecretKey, publicKeyOf, sign } from './crypto'
import { canonicalJson, utf8 } from './encoding'
import { createIdentity } from './identity'
import { founderOf, initLocalVault } from './init'
import { localLayout } from './layout'
import { withLock } from './lock'
import { handover, ownerDoc, readOwner } from './owner-trust'
import { rotateOwner } from './rotate'
import { loadState } from './state'
import { Txn } from './txn'
import { readSnapshot, Vault } from './vault'

let root: string
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'tv-handover-'))
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

async function setup() {
  const env = { XDG_CONFIG_HOME: root }
  const alice = await createIdentity('alice', 'machine')
  const { layout } = await initLocalVault(join(root, 'vault'), founderOf(alice.identity), env)
  const manage = async () => new Admin(await Vault.open(layout, [alice.key], env))
  for (const name of ['bob', 'carol']) {
    const { identity } = await createIdentity(name, 'machine')
    await (await manage()).addMember(name, { ...founderOf(identity).member, owner: true, tiers: [] })
  }
  const remote = localLayout(layout.vault, { XDG_CONFIG_HOME: join(root, 'remote') })
  const trusted = loadState(remote, {}).owner.signPublic
  return { layout, remote, manage, trusted, env, key: alice.key }
}

it.each([
  ['after a rotation', true],
  ['before any rotation', false],
])('refuses a handover chain claiming another first owner %s', async (_, rotate) => {
  // given a machine that trusts the current owner
  const { layout, remote, manage } = await setup()
  if (rotate) await (await manage()).removeMember('bob')
  loadState(remote, {})

  // when the chain is replaced by a valid one that a random key signed into the current owner
  const { recipient, signPublic } = readOwner(layout)
  const to = { recipient, signPublic }
  const random = await generateSecretKey({ kind: 'owner' })
  const from = (await publicKeyOf(random)).signPublic
  const sig = sign(random.signSecret, utf8(canonicalJson({ purpose: 'typevault:handover', from, to })))
  writeFileSync(layout.ownerFile, ownerDoc(to, [{ from, to, sig }]))

  // then the machine refuses the new origin, which would name a different audit chain
  expect(() => loadState(remote, {})).toThrow(expect.objectContaining({ code: 'tampered' }))
})

it('opens the vault only after a rotation in progress has published', async () => {
  // given a rotation holding the vault lock, with owner.json not yet written
  const { layout, env, key } = await setup()
  const published = readFileSync(layout.ownerFile, 'utf8')
  const { promise: entered, resolve: enter } = Promise.withResolvers<void>()
  const { promise: finish, resolve: release } = Promise.withResolvers<void>()
  const rotation = withLock(layout.lockFile, 'exclusive', async () => {
    writeFileSync(layout.ownerFile, '{')
    enter()
    await finish
    writeFileSync(layout.ownerFile, published)
  })
  await entered

  // when the vault is opened meanwhile
  const opening = Vault.open(layout, [key], env)
  release()
  await rotation

  // then it reads the finished state, not the half-written one
  expect((await opening).keyring.owner).toBeDefined()
})

it.each(['vault open', 'CLI pin check'] as const)(
  '%s finishes an interrupted rotation queued ahead of it',
  async (reader) => {
    // given a writer holding the lock before publishing a rotation journal
    const { layout, env, key, trusted } = await setup()
    const vault = await Vault.open(layout, [key], env)
    const owner = vault.keyring.owner
    if (owner === undefined) throw new Error('expected the original owner key')
    const txn = new Txn()
    await rotateOwner({ vault, owner, state: vault.state, txn, exposed: false })
    const { promise: entered, resolve: enter } = Promise.withResolvers<void>()
    const { promise: finish, resolve: release } = Promise.withResolvers<void>()
    const writer = withLock(layout.lockFile, 'exclusive', async () => {
      enter()
      await finish
      const staged = join(layout.txnDir, 'interrupted')
      mkdirSync(join(staged, 'files'), { recursive: true })
      for (const [index, bytes] of [...txn.puts.values()].entries())
        writeFileSync(join(staged, 'files', String(index)), bytes)
      writeFileSync(
        join(staged, 'manifest.json'),
        JSON.stringify({ puts: [...txn.puts.keys()], removes: [...txn.removes] }),
      )
      writeFileSync(join(staged, 'COMMITTED'), '')
      const index = [...txn.puts.keys()].indexOf('members.json')
      const manifest = join(staged, 'files', String(index))
      writeFileSync(layout.membersFile, readFileSync(manifest))
      rmSync(manifest)
    })
    await entered

    // when the reader starts and the writer releases the lock with the rotation partly applied
    const pin = { ...env, TYPEVAULT_OWNER: trusted }
    const reading = (async () => {
      switch (reader) {
        case 'vault open': {
          const opened = await Vault.open(layout, [key], env)
          const unwrapped = opened.keyring.owner
          return unwrapped === undefined ? undefined : (await publicKeyOf(unwrapped)).signPublic
        }
        case 'CLI pin check':
          // What the live CLI's TYPEVAULT_OWNER check runs before it reaches a daemon.
          return (await readSnapshot(layout, pin, async () => loadState(layout, pin))).owner.signPublic
      }
    })()
    release()
    const [current] = await Promise.all([reading, writer])

    // then both read the recovered rotation: the vault opens with the new key, and the pin check accepts its handover
    expect(current).not.toBe(trusted)
    expect(current).toBe(readOwner(layout).signPublic)
  },
)

it('advances through missed handovers but never back to a pinned ancestor', async () => {
  // given a machine that trusted the original key and kept an env pin to it
  const { layout, remote, manage, trusted } = await setup()
  const pin = { TYPEVAULT_OWNER: trusted }
  const backup = join(root, 'backup')
  cpSync(layout.vault, backup, { recursive: true })

  // when it skips two rotations, even a vault without tiers must have all four manifests re-signed
  const before = loadState(remote, pin).seqs
  await (await manage()).removeMember('bob')
  await (await manage()).removeMember('carol')
  const next = loadState(remote, pin)
  expect(next.owner.signPublic).not.toBe(trusted)
  expect(next.seqs).toEqual({
    tiers: before.tiers + 2,
    members: before.members + 2,
    ceilings: before.ceilings + 2,
    signers: before.signers + 2,
  })
  expect(JSON.parse(readFileSync(remote.trustFile, 'utf8')).ownerSignPublic).toBe(next.owner.signPublic)

  // then even restoring the complete old signed vault cannot roll the local pin back
  cpSync(backup, layout.vault, { recursive: true })
  rmSync(remote.revisionsFile) // Test the owner pin independently of manifest sequence marks.
  expect(() => loadState(remote, pin)).toThrow(expect.objectContaining({ code: 'tampered' }))
  const fresh = localLayout(layout.vault, { XDG_CONFIG_HOME: join(root, 'fresh') })
  expect(() => loadState(fresh, { TYPEVAULT_OWNER: next.owner.signPublic })).toThrow(
    expect.objectContaining({ code: 'tampered' }),
  )
})

it("keeps a state directory's audit chain across owner rotations", async () => {
  // given a vault whose audit anchors live under an explicit state directory
  const { layout, manage } = await setup()
  const env = { XDG_CONFIG_HOME: root, TYPEVAULT_STATE_DIR: join(root, 'state') }
  const before = localLayout(layout.vault, env).anchorsFile

  // when the owner key rotates
  await (await manage()).removeMember('bob')

  // then the anchors already committed for this chain are still the ones checked
  expect(localLayout(layout.vault, env).anchorsFile).toBe(before)
})

it('rejects a shortened owner history after trusting the current owner', async () => {
  // given a machine that has seen the handover to the current owner
  const { layout, remote, manage } = await setup()
  await (await manage()).removeMember('bob')
  loadState(remote, {})

  // when only the handovers are removed, leaving the current owner and signed manifests intact
  const { recipient, signPublic } = readOwner(layout)
  writeFileSync(layout.ownerFile, ownerDoc({ recipient, signPublic }))

  // then reloading the vault rejects the shortened history
  expect(() => loadState(remote, {})).toThrow(expect.objectContaining({ code: 'tampered' }))
})

it('verifies the audit log against the validated owner chain, not a later owner.json', async () => {
  // given an anchored log under a state directory, and the owner chain validated for it
  const { layout } = await setup()
  const state = localLayout(layout.vault, { XDG_CONFIG_HOME: root, TYPEVAULT_STATE_DIR: join(root, 'state') })
  await appendAudit(state, { action: 'read', mode: 'direct', entries: ['openai'] })
  await anchorAudit(state)
  const anchors = state.anchorsFileFor(loadState(state, {}).origin)

  // when owner.json changes afterwards and the local log goes missing
  writeFileSync(layout.ownerFile, '{')
  rmSync(state.auditLog)

  // then verification still checks the validated chain's anchors
  expect(verifyAudit(state, anchors)).toMatchObject({ ok: false, reason: expect.stringContaining('anchor') })
})

it('refuses to rotate when owner.json no longer names the owner the rotation validated', async () => {
  // given a vault opened on its current owner, whose owner.json is then replaced underneath it, as a git pull would
  const { layout, env, key } = await setup()
  const vault = await Vault.open(layout, [key], env)
  const owner = vault.keyring.owner
  if (owner === undefined) throw new Error('expected the owner key')
  const other = await createIdentity('mallory', 'machine')
  const { layout: elsewhere } = await initLocalVault(join(root, 'other'), founderOf(other.identity), env)
  writeFileSync(layout.ownerFile, readFileSync(elsewhere.ownerFile))

  // when the rotation prepares its writes
  const txn = new Txn()
  const rotating = rotateOwner({ vault, owner, state: vault.state, txn, exposed: true })

  // then it stops before staging a handover from an owner it doesn't sign for
  await expect(rotating).rejects.toMatchObject({ code: 'conflict' })
  expect(txn.puts.has('owner.json')).toBe(false)
})

it('refuses to rotate when only the owner history changed underneath it', async () => {
  // given a vault opened on its current owner, whose owner.json then gains a different history for the same key
  const { layout, env, key } = await setup()
  const vault = await Vault.open(layout, [key], env)
  const owner = vault.keyring.owner
  if (owner === undefined) throw new Error('expected the owner key')
  const { recipient, signPublic } = readOwner(layout)
  const forger = await generateSecretKey({ kind: 'owner' })
  const from = { ...(await publicKeyOf(forger)), handovers: [] }
  writeFileSync(
    layout.ownerFile,
    ownerDoc({ recipient, signPublic }, handover(from, forger, { recipient, signPublic })),
  )

  // when the rotation prepares its writes
  const txn = new Txn()
  const rotating = rotateOwner({ vault, owner, state: vault.state, txn, exposed: true })

  // then it stops before carrying that history into the new owner.json
  await expect(rotating).rejects.toMatchObject({ code: 'conflict' })
  expect(txn.puts.has('owner.json')).toBe(false)
})

it('rejects a handover signed by an unrelated key without changing trust', async () => {
  // given a genuine successor with intact manifests
  const { layout, remote, manage, trusted } = await setup()
  await (await manage()).removeMember('bob')
  const owner = readOwner(layout)
  const [link] = owner.handovers
  if (!link) throw new Error('expected an owner handover')

  // when a random key signs exactly the same endorsement
  const random = await generateSecretKey({ kind: 'owner' })
  const sig = sign(
    random.signSecret,
    utf8(canonicalJson({ purpose: 'typevault:handover', from: trusted, to: link.to })),
  )
  writeFileSync(layout.ownerFile, JSON.stringify({ ...owner, handovers: [{ ...link, sig }] }))

  // then an already trusting machine refuses it and leaves its pin unchanged
  expect(() => loadState(remote, {})).toThrow(expect.objectContaining({ code: 'tampered' }))
  expect(JSON.parse(readFileSync(remote.trustFile, 'utf8')).ownerSignPublic).toBe(trusted)
  const stateDir = localLayout(layout.vault, { TYPEVAULT_STATE_DIR: join(root, 'state') })
  expect(() => stateDir.anchorsFile).toThrow(expect.objectContaining({ code: 'tampered' }))
})
