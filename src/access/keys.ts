import { decodeSecretKey, type SecretKey } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { readIdentity } from '../core/identity'

/**
 * The member keys this process holds without anyone typing a password: `TYPEVAULT_KEY`, else a machine identity.
 * A human identity yields nothing here; it is unlocked once with `typevault unlock`.
 */
export function machineKeys(env: Readonly<Record<string, string | undefined>>): readonly SecretKey[] {
  const explicit = env['TYPEVAULT_KEY']
  if (explicit !== undefined && explicit !== '') {
    const key = decodeSecretKey(explicit)
    if (key.role.kind !== 'member') throw new TypeVaultError('invalid', 'TYPEVAULT_KEY must be a member key')
    return [key]
  }
  const identity = readIdentity(env)
  return identity?.kind === 'machine' ? [decodeSecretKey(identity.key)] : []
}
