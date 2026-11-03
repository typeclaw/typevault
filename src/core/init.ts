import { existsSync } from 'node:fs'
import { join } from 'node:path'

import { encodeSecretKey, generateSecretKey, type PublicKey, publicKeyOf, type SecretKey } from './crypto'
import { TypeVaultError } from './errors'
import { atomicWrite, ensureDir } from './fsx'
import { type Layout, layoutOf, localLayout } from './layout'
import { ceilingsDoc, groupsDoc, signersDoc } from './state'

type Env = Readonly<Record<string, string | undefined>>

/** Ignores everything in the vault directory except `vault/`, the only part that is safe to commit. */
const ROOT_GITIGNORE = '/*\n!/vault/\n!/.gitignore\n'

/** Creates an empty global vault and its operator key. The operator key is the recovery path; keep a copy offline. */
export async function initVault(root: string): Promise<SecretKey> {
  const layout = layoutOf(root)
  refuseExisting(layout.operatorFile, root)
  const operatorKey = await generateSecretKey({ kind: 'operator' })
  await writeVault(layout, operatorKey, await publicKeyOf(operatorKey))
  atomicWrite(join(layout.root, '.gitignore'), ROOT_GITIGNORE)
  return operatorKey
}

/** Creates an empty project vault at `dir` (all of it safe to commit); its keys go under the typevault root. */
export async function initLocalVault(dir: string, env: Env = process.env): Promise<Layout> {
  refuseExisting(join(dir, 'operator.json'), dir)
  const operatorKey = await generateSecretKey({ kind: 'operator' })
  const operator = await publicKeyOf(operatorKey)
  const layout = localLayout(dir, operator.signPublic, env)
  await writeVault(layout, operatorKey, operator)
  return layout
}

function refuseExisting(operatorFile: string, where: string): void {
  if (existsSync(operatorFile)) throw new TypeVaultError('conflict', `a vault already exists at ${where}`)
}

async function writeVault(layout: Layout, operatorKey: SecretKey, operator: PublicKey): Promise<void> {
  for (const dir of [layout.keys, layout.groupKeys, layout.audit, layout.run]) ensureDir(dir, 0o700)
  ensureDir(layout.entries)
  atomicWrite(layout.operatorKey, `${encodeSecretKey(operatorKey)}\n`, 0o600)
  atomicWrite(layout.groupsFile, groupsDoc({}, operatorKey, 1))
  atomicWrite(layout.signersFile, signersDoc({}, operatorKey, 1))
  atomicWrite(layout.ceilingsFile, ceilingsDoc({}, operatorKey, 1))
  atomicWrite(layout.trustFile, JSON.stringify({ operatorSignPublic: operator.signPublic }), 0o600)
  // operator.json last: its presence is what marks the directory as an initialized vault.
  atomicWrite(layout.operatorFile, `${JSON.stringify({ v: 1, ...operator }, null, 2)}\n`)
}
