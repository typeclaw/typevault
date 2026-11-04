import { existsSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { encodeSecretKey, generateSecretKey, type PublicKey, publicKeyOf, seal, type SecretKey } from './crypto'
import { utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { atomicWrite, ensureDir } from './fsx'
import { type Identity, type MemberPublic, memberPublicOfIdentity, sealedCopyPath } from './identity'
import { ownerWrapPath } from './keyring'
import { type Layout, layoutOf, localLayout } from './layout'
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

/** Ignores everything in the vault directory except `vault/`, the only part that is safe to commit. */
const ROOT_GITIGNORE = '/*\n!/vault/\n!/.gitignore\n'

/**
 * Creates an empty global vault owned by `founder`. The owner key is never written down in the clear: it exists only
 * wrapped to owner members, so the founder's password and Secret Key are the recovery path.
 */
export async function initVault(root: string, founder: Founder): Promise<Created> {
  const layout = layoutOf(root)
  refuseExisting(layout.ownerFile, root)
  const owner = await writeVault(layout, founder)
  atomicWrite(join(layout.root, '.gitignore'), ROOT_GITIGNORE)
  return { layout, owner }
}

/** Creates an empty project vault at `dir`, all of it safe to commit. */
export async function initLocalVault(dir: string, founder: Founder, env: Env = process.env): Promise<Created> {
  refuseExisting(join(dir, 'owner.json'), dir)
  const layout = localLayout(dir, env)
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
  // session token, revision marks) belongs to the old vault, so it goes; the trust pin is rewritten below.
  rmSync(layout.run, { recursive: true, force: true })
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
