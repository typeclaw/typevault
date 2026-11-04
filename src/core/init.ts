import { existsSync, readdirSync, rmSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'

import { encodeSecretKey, generateSecretKey, type PublicKey, publicKeyOf, seal, type SecretKey } from './crypto'
import { utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { atomicWrite, ensureDir } from './fsx'
import { type Identity, type MemberPublic, memberPublicOfIdentity, sealedCopyPath } from './identity'
import { ownerWrapPath } from './keyring'
import { globalLayout, type Layout, localLayout } from './layout'
import { ceilingsDoc, membersDoc, parseMemberName, signersDoc, tiersDoc } from './state'

type Env = Readonly<Record<string, string | undefined>>

/** The first member, who becomes the owner. A human's password-sealed key is committed beside the vault. */
export type Founder = { readonly name: string; readonly member: MemberPublic; readonly sealedKey?: string }

export const founderOf = (identity: Identity): Founder => ({
  name: identity.name,
  member: memberPublicOfIdentity(identity),
  ...(identity.kind === 'human' ? { sealedKey: identity.sealedKey } : {}),
})

export type Created = { readonly layout: Layout; readonly owner: SecretKey }

/**
 * Creates an empty global vault owned by `founder`, all of it safe to commit. The owner key is never written down in
 * the clear: it exists only wrapped to owner members, so the founder's password and Secret Key are the recovery path.
 */
export const initGlobalVault = (founder: Founder, env: Env = process.env): Promise<Created> =>
  create(globalLayout(env), founder)

/** Creates an empty project vault at `dir`, all of it safe to commit. */
export const initLocalVault = (dir: string, founder: Founder, env: Env = process.env): Promise<Created> =>
  create(localLayout(dir, env), founder)

async function create(layout: Layout, founder: Founder): Promise<Created> {
  refuseExisting(layout.ownerFile, layout.vault)
  return { layout, owner: await writeVault(layout, founder) }
}

function refuseExisting(ownerFile: string, where: string): void {
  if (existsSync(ownerFile)) throw new TypeVaultError('conflict', `a vault already exists at ${where}`)
  // Pre-rename vaults are not migrated; init over one would keep its stale runtime state (revision marks).
  if (existsSync(join(dirname(ownerFile), 'operator.json'))) {
    throw new TypeVaultError(
      'conflict',
      `an old-format vault (operator.json) exists at ${where}; move it and its typevault root aside, then run init again`,
    )
  }
}

async function writeVault(layout: Layout, founder: Founder): Promise<SecretKey> {
  const name = parseMemberName(founder.name)
  // A vault re-created at the same place reuses this checkout's state directory. Its runtime state (grants, a
  // session token, revision marks) belongs to the old vault, so it goes; the trust pin is rewritten below. The daemon
  // lock and claim stay: whoever initializes may hold them to keep a daemon from starting meanwhile.
  const kept = new Set([basename(layout.daemonLock), basename(layout.daemonHolder)])
  for (const name of existsSync(layout.run) ? readdirSync(layout.run) : []) {
    if (!kept.has(name)) rmSync(join(layout.run, name), { recursive: true, force: true })
  }
  const ownerKey = await generateSecretKey({ kind: 'owner' })
  const owner: PublicKey = await publicKeyOf(ownerKey)
  const { kind, recipient, signPublic } = founder.member
  for (const dir of [layout.audit, layout.run]) ensureDir(dir, 0o700)
  ensureDir(layout.entries)
  atomicWrite(layout.tiersFile, tiersDoc({}, ownerKey, 1))
  atomicWrite(
    layout.membersFile,
    membersDoc({ [name]: { kind, recipient, signPublic, owner: true, tiers: [] } }, ownerKey, 1),
  )
  atomicWrite(layout.signersFile, signersDoc({}, ownerKey, 1))
  atomicWrite(layout.ceilingsFile, ceilingsDoc({}, ownerKey, 1))
  atomicWrite(join(layout.vault, ownerWrapPath(name)), await seal([recipient], utf8(encodeSecretKey(ownerKey))))
  if (founder.sealedKey !== undefined) atomicWrite(sealedCopyPath(layout, name), founder.sealedKey)
  atomicWrite(layout.trustFile, JSON.stringify({ ownerSignPublic: owner.signPublic }), 0o600)
  // owner.json last: its presence is what marks the directory as an initialized vault.
  atomicWrite(layout.ownerFile, `${JSON.stringify({ v: 1, ...owner }, null, 2)}\n`)
  return ownerKey
}
