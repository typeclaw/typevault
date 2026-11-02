import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { decodeSecretKey, type SecretKey } from '../core/crypto'
import type { Layout } from '../core/layout'

/** `TYPEVAULT_KEY` alone when set; otherwise the operator key and group keys in the key directory. */
export function loadLocalKeys(layout: Layout, env: Readonly<Record<string, string | undefined>>): readonly SecretKey[] {
  const explicit = env['TYPEVAULT_KEY']
  if (explicit !== undefined && explicit !== '') return [decodeSecretKey(explicit)]
  const operator = existsSync(layout.operatorKey) ? [decodeSecretKey(readFileSync(layout.operatorKey, 'utf8'))] : []
  const groups = existsSync(layout.groupKeys)
    ? readdirSync(layout.groupKeys)
        .filter((file) => file.endsWith('.key'))
        .map((file) => decodeSecretKey(readFileSync(join(layout.groupKeys, file), 'utf8')))
    : []
  return [...operator, ...groups]
}
