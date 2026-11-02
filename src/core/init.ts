import { existsSync } from 'node:fs'
import { join } from 'node:path'

import { encodeSecretKey, generateSecretKey, publicKeyOf, type SecretKey } from './crypto'
import { TypeVaultError } from './errors'
import { atomicWrite, ensureDir } from './fsx'
import { layoutOf } from './layout'
import { ceilingsDoc, groupsDoc, signersDoc } from './state'

/** Ignores everything in the vault directory except `vault/`, the only part that is safe to commit. */
const ROOT_GITIGNORE = '/*\n!/vault/\n!/.gitignore\n'
const VAULT_GITIGNORE = '.txn/\n'

/** Creates an empty vault and its operator key. The operator key is the recovery path; keep a copy offline. */
export async function initVault(root: string): Promise<SecretKey> {
  const layout = layoutOf(root)
  if (existsSync(layout.operatorFile)) throw new TypeVaultError('conflict', `a vault already exists at ${root}`)
  for (const dir of [layout.keys, layout.groupKeys, layout.audit, layout.run]) ensureDir(dir, 0o700)
  ensureDir(layout.entries)
  const operatorKey = await generateSecretKey({ kind: 'operator' })
  const operator = await publicKeyOf(operatorKey)
  atomicWrite(layout.operatorKey, `${encodeSecretKey(operatorKey)}\n`, 0o600)
  atomicWrite(layout.groupsFile, groupsDoc({}, operatorKey))
  atomicWrite(layout.signersFile, signersDoc({}, operatorKey))
  atomicWrite(layout.ceilingsFile, ceilingsDoc({}, operatorKey))
  atomicWrite(join(layout.vault, '.gitignore'), VAULT_GITIGNORE)
  atomicWrite(join(layout.root, '.gitignore'), ROOT_GITIGNORE)
  atomicWrite(layout.trustFile, JSON.stringify({ operatorSignPublic: operator.signPublic }), 0o600)
  // operator.json last: its presence is what marks the directory as an initialized vault.
  atomicWrite(layout.operatorFile, `${JSON.stringify({ v: 1, ...operator }, null, 2)}\n`)
  return operatorKey
}
