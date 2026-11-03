import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { encodeSecretKey, generateSecretKey, type PublicKey, publicKeyOf, type SecretKey } from './crypto'
import { TypeVaultError } from './errors'
import { atomicWrite, ensureDir } from './fsx'
import { type Layout, layoutOf, localLayout } from './layout'
import { ceilingsDoc, groupsDoc, signersDoc } from './state'

type Env = Readonly<Record<string, string | undefined>>

/** Ignores everything in the vault directory except `vault/`, the only part that is safe to commit. */
const ROOT_GITIGNORE = '/*\n!/vault/\n!/.gitignore\n'

/** Creates an empty global vault and its owner key. The owner key is the recovery path; keep a copy offline. */
export async function initVault(root: string): Promise<SecretKey> {
  const layout = layoutOf(root)
  refuseExisting(layout.ownerFile, root)
  const ownerKey = await generateSecretKey({ kind: 'owner' })
  await writeVault(layout, ownerKey, await publicKeyOf(ownerKey))
  atomicWrite(join(layout.root, '.gitignore'), ROOT_GITIGNORE)
  return ownerKey
}

/** Creates an empty project vault at `dir` (all of it safe to commit); its keys go under the typevault root. */
export async function initLocalVault(dir: string, env: Env = process.env): Promise<Layout> {
  refuseExisting(join(dir, 'owner.json'), dir)
  const ownerKey = await generateSecretKey({ kind: 'owner' })
  const owner = await publicKeyOf(ownerKey)
  const layout = localLayout(dir, owner.signPublic, env)
  await writeVault(layout, ownerKey, owner)
  return layout
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

async function writeVault(layout: Layout, ownerKey: SecretKey, owner: PublicKey): Promise<void> {
  for (const dir of [layout.keys, layout.groupKeys, layout.audit, layout.run]) ensureDir(dir, 0o700)
  ensureDir(layout.entries)
  atomicWrite(layout.ownerKey, `${encodeSecretKey(ownerKey)}\n`, 0o600)
  atomicWrite(layout.groupsFile, groupsDoc({}, ownerKey, 1))
  atomicWrite(layout.signersFile, signersDoc({}, ownerKey, 1))
  atomicWrite(layout.ceilingsFile, ceilingsDoc({}, ownerKey, 1))
  atomicWrite(layout.trustFile, JSON.stringify({ ownerSignPublic: owner.signPublic }), 0o600)
  // owner.json last: its presence is what marks the directory as an initialized vault.
  atomicWrite(layout.ownerFile, `${JSON.stringify({ v: 1, ...owner }, null, 2)}\n`)
}
