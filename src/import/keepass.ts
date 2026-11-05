import { argon2d, argon2id } from 'hash-wasm'
import { Consts, Credentials, CryptoEngine, Kdbx, KdbxError, ProtectedValue, type KdbxGroup } from 'kdbxweb'
import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { collectEntries, parseExternal, type ImportItem } from './shared'
import type { ImportResult } from './types'

CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type, version) => {
  if (version !== 0x13) throw new TypeVaultError('invalid', 'unsupported KeePass Argon2 version')
  const hash = type === CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d
  const result = await hash({
    password: new Uint8Array(password),
    salt: new Uint8Array(salt),
    memorySize: memory,
    iterations,
    hashLength: length,
    parallelism,
    outputType: 'binary',
  })
  return new Uint8Array(result).buffer
})

export async function parseKeepass(bytes: Uint8Array, password?: string): Promise<ImportResult> {
  if (password === undefined) throw new TypeVaultError('invalid', 'KeePass import requires a password')
  parseExternal(bytes, z.instanceof(Uint8Array), 'KeePass')
  parseExternal(password, z.string(), 'KeePass password')
  let db: Kdbx
  try {
    db = await Kdbx.load(new Uint8Array(bytes).buffer, new Credentials(ProtectedValue.fromString(password)))
  } catch (error) {
    if (error instanceof KdbxError) {
      if (error.code === Consts.ErrorCodes.InvalidKey) throw new TypeVaultError('denied', 'incorrect KeePass password')
      throw new TypeVaultError('invalid', 'invalid or unsupported KeePass database')
    }
    if (error instanceof RangeError) throw new TypeVaultError('invalid', 'invalid KeePass database')
    throw error
  }
  const items: ImportItem[] = []
  const warnings: string[] = []
  const visit = (group: KdbxGroup, root: boolean) => {
    if (group.uuid.equals(db.meta.recycleBinUuid)) return
    const container = root ? undefined : parseExternal(group.name, z.string().optional(), 'KeePass group')
    for (const entry of group.entries) {
      const fields = parseExternal(
        Object.fromEntries(
          [...entry.fields].map(([key, value]) => [key, value instanceof ProtectedValue ? value.getText() : value]),
        ),
        z.record(z.string(), z.string()),
        'KeePass fields',
      )
      const login = ['UserName', 'Password', 'URL', 'otp'].some((key) => Boolean(fields[key]))
      if (!login && !fields['Notes']) {
        warnings.push('skipped KeePass entry without supported fields')
        continue
      }
      const url = fields['URL']
      items.push({
        title: fields['Title'] ?? '',
        preset: login ? 'password' : 'note',
        fields: login
          ? { username: fields['UserName'], password: fields['Password'], url, totp: fields['otp'] }
          : { $default: fields['Notes'] },
        tags: parseExternal(entry.tags, z.array(z.string()).readonly(), 'KeePass tags'),
        source: `keepass:${entry.uuid.id}`,
        ...(container === undefined ? {} : { container }),
        ...(url === undefined ? {} : { url }),
      })
    }
    for (const child of group.groups) visit(child, false)
  }
  for (const group of db.groups) visit(group, true)
  return collectEntries(items, warnings)
}
