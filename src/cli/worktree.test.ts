import { expect, it } from 'bun:test'
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { z } from 'zod'

import { generateSecretKey, publicKeyOf } from '../core/crypto'
import { createIdentity, encodeMemberPublic, memberPublicOfIdentity } from '../core/identity'
import { localLayout } from '../core/layout'
import { handover, ownerDoc, readOwner } from '../core/owner-trust'
import { callDaemon, servingPid } from '../daemon/client'
import { addWorktree, base, cli, git, LOCKED, main, owner, PASSWORD, succeeds } from './worktree.harness'

it('shares a session unlocked in one worktree with the others, and locks them together', async () => {
  // given a linked worktree of the repository, and the vault unlocked in the main one
  const worktree = join(base, 'wt')
  succeeds(await git(['worktree', 'add', '-q', worktree], main))
  expect((await cli(['ls'], worktree)).stderr).toContain(LOCKED)
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))

  // when an agent reads in the worktree, with no password to give
  const read = succeeds(await cli(['ls', '--json'], worktree))

  // then it reads the worktree's own vault through the shared session
  expect(JSON.parse(read.stdout)).toMatchObject([{ name: 'openai' }])

  // and locking in the worktree locks the main one too, so nothing is shared back
  expect(succeeds(await cli(['lock'], worktree)).stdout).toBe('locked\n')
  expect((await cli(['ls'], main)).stderr).toContain(LOCKED)
  expect((await cli(['ls'], worktree)).stderr).toContain(LOCKED)
}, 60_000)

it('ends a grant issued in a worktree whose daemon already stopped', async () => {
  // given a grant issued in a worktree with its own session, whose daemon then stops
  const worktree = await addWorktree()
  succeeds(await cli(['unlock', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))
  const issued = await cli(['grant', '--tier', 'default', '--ttl', '1h', '--label', 'agent'], worktree)
  const token = succeeds(issued).stdout.trim()
  succeeds(await cli(['daemon', 'stop'], worktree))
  // and whose owner.json is the same owner, written differently
  const ownerFile = join(worktree, '.typevault', 'owner.json')
  writeFileSync(ownerFile, JSON.stringify(JSON.parse(readFileSync(ownerFile, 'utf8')), null, 4))

  // when the vault is locked from the main worktree, and the other one unlocked again
  succeeds(await cli(['lock'], main))
  succeeds(await cli(['unlock', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))

  // then the grant is refused there
  owner['TYPEVAULT_GRANT'] = token
  expect((await cli(['ls'], worktree)).stderr).toContain('unknown grant')
})

it('stops a worktree daemon on an older owner generation and revokes its live grants', async () => {
  // given a linked worktree with a running daemon and a usable grant, still on the original owner
  const worktree = await addWorktree()
  succeeds(await cli(['unlock', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))
  const token = succeeds(await cli(['grant', '--tier', 'default'], worktree)).stdout.trim()
  owner['TYPEVAULT_GRANT'] = token
  succeeds(await cli(['ls'], worktree))
  delete owner['TYPEVAULT_GRANT']
  const { identity } = await createIdentity('bob', 'machine')
  const key = encodeMemberPublic(memberPublicOfIdentity(identity))
  succeeds(await cli(['member', 'add', 'bob', key, '--owner', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  succeeds(await cli(['member', 'rm', 'bob', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  const { agentSocket } = localLayout(join(worktree, '.typevault'), owner)
  expect(await servingPid(agentSocket)).toBeNumber()

  // when the rotated checkout locks the vault
  succeeds(await cli(['lock'], main))

  // then the daemon is gone and the old token cannot be reused even after unlocking again
  expect(await servingPid(agentSocket)).toBeUndefined()
  succeeds(await cli(['unlock', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))
  try {
    owner['TYPEVAULT_GRANT'] = token
    expect((await cli(['ls'], worktree)).stderr).toContain('unknown grant')
  } finally {
    delete owner['TYPEVAULT_GRANT']
  }
}, 60_000)

it('locks a worktree on an older owner generation even when its history claims another origin', async () => {
  // given a worktree with a live grant on the original owner, whose owner.json then claims a different origin
  const worktree = await addWorktree()
  succeeds(await cli(['unlock', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))
  succeeds(await cli(['grant', '--tier', 'default'], worktree))
  const { identity } = await createIdentity('bob', 'machine')
  const key = encodeMemberPublic(memberPublicOfIdentity(identity))
  succeeds(await cli(['member', 'add', 'bob', key, '--owner', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  succeeds(await cli(['member', 'rm', 'bob', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  const layout = localLayout(join(worktree, '.typevault'), owner)
  const { recipient, signPublic } = readOwner(layout)
  const forger = await generateSecretKey({ kind: 'owner' })
  const from = { ...(await publicKeyOf(forger)), handovers: [] }
  writeFileSync(
    layout.ownerFile,
    ownerDoc({ recipient, signPublic }, handover(from, forger, { recipient, signPublic })),
  )
  expect(existsSync(layout.grantsFile)).toBe(true)

  // when the rotated checkout locks the vault
  succeeds(await cli(['lock'], main))

  // then the worktree's current key, an earlier owner of this vault, still marks it as the same vault
  expect(await servingPid(layout.agentSocket)).toBeUndefined()
  expect(existsSync(layout.grantsFile)).toBe(false)
}, 60_000)

it('locks a worktree that rotated its owner independently from the same earlier owner', async () => {
  // given two more owners committed in the vault, and a worktree holding a live grant
  for (const name of ['bob', 'carol']) {
    const { identity } = await createIdentity(name, 'machine')
    const key = encodeMemberPublic(memberPublicOfIdentity(identity))
    succeeds(await cli(['member', 'add', name, key, '--owner', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  }
  succeeds(await git(['add', '-A'], main))
  succeeds(await git(['commit', '-q', '-m', 'owners'], main))
  const worktree = await addWorktree()
  succeeds(await cli(['unlock', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))
  const token = succeeds(await cli(['grant', '--tier', 'default'], worktree)).stdout.trim()

  // when each checkout removes a different owner, so their histories diverge from the same original owner
  succeeds(await cli(['member', 'rm', 'carol', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))
  succeeds(await cli(['member', 'rm', 'bob', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  const layout = localLayout(join(worktree, '.typevault'), owner)
  expect(existsSync(layout.grantsFile)).toBe(true)
  succeeds(await cli(['lock'], main))

  // then the worktree's grant is ended, and stays unknown once the worktree unlocks again
  expect(existsSync(layout.grantsFile)).toBe(false)
  succeeds(await cli(['unlock', '--vault-password-stdin'], worktree, `${PASSWORD}\n`))
  try {
    owner['TYPEVAULT_GRANT'] = token
    expect((await cli(['ls'], worktree)).stderr).toContain('unknown grant')
  } finally {
    delete owner['TYPEVAULT_GRANT']
  }
}, 60_000)

it("still ends grants in a worktree whose owner can't be read", async () => {
  // given a worktree with grants and a damaged owner.json
  const worktree = await addWorktree()
  const vault = join(worktree, '.typevault')
  writeFileSync(join(vault, 'owner.json'), '{not json')
  const { grantsFile, run: runDir } = localLayout(vault, owner)
  mkdirSync(runDir, { recursive: true })
  writeFileSync(grantsFile, '[]')

  // when the vault is locked from the main worktree
  succeeds(await cli(['lock'], main))

  // then its grants are gone
  expect(existsSync(grantsFile)).toBe(false)
})

it('leaves the grants of a different vault in a worktree alone', async () => {
  // given a worktree whose vault has another owner, with grants of its own
  const worktree = await addWorktree()
  const vault = join(worktree, '.typevault')
  writeFileSync(join(vault, 'owner.json'), JSON.stringify({ recipient: 'age1other', signPublic: 'other' }))
  const { grantsFile, run: runDir } = localLayout(vault, owner)
  mkdirSync(runDir, { recursive: true })
  writeFileSync(grantsFile, '[]')

  // when the vault is locked from the main worktree
  succeeds(await cli(['lock'], main))

  // then that vault's grants are still there
  expect(existsSync(grantsFile)).toBe(true)
})

it('shares no session with a copy of the vault or a clone of the repository', async () => {
  // given the vault unlocked in the repository, a clone of it, and a bare copy of the vault
  succeeds(await cli(['unlock', '--vault-password-stdin'], main, `${PASSWORD}\n`))
  const clone = join(base, 'clone')
  succeeds(await git(['clone', '-q', main, clone], base))
  const copy = join(base, 'copy')
  cpSync(join(main, '.typevault'), join(copy, '.typevault'), { recursive: true })

  // then both stay locked
  expect((await cli(['ls'], clone)).stderr).toContain(LOCKED)
  expect((await cli(['ls'], copy)).stderr).toContain(LOCKED)

  // and the session refuses to start in either, even asked directly with its own token
  const layout = localLayout(join(main, '.typevault'), owner)
  const token = readFileSync(layout.sessionFile, 'utf8').trim()
  const Ok = z.object({ ok: z.literal(true) })
  for (const vault of [join(clone, '.typevault'), join(copy, '.typevault')]) {
    await expect(callDaemon(layout.agentSocket, '/v1/attach', { vault }, Ok, { token })).rejects.toMatchObject({
      code: 'denied',
    })
  }
}, 60_000)
