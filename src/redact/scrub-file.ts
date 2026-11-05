import { randomUUID } from 'node:crypto'
import { lstat, open, rename, rm } from 'node:fs/promises'
import { dirname, join } from 'node:path'

import { TypeVaultError } from '../core/errors'
import type { Redactor } from './index'

export async function scrubFile(path: string, redactor: Redactor): Promise<boolean> {
  let temporary: string | undefined
  try {
    try {
      const info = await lstat(path)
      if (info.isSymbolicLink())
        throw new TypeVaultError('invalid', 'Refusing to scrub a symbolic link; name its target')
      if (!info.isFile()) throw new TypeVaultError('invalid', 'Not a regular file')
      const original = await open(path, 'r')
      const snapshot = await (async () => {
        try {
          return { bytes: await original.readFile(), mode: (await original.stat()).mode & 0o7777 }
        } finally {
          await original.close()
        }
      })()
      const redacted = Buffer.from(
        await new Response(new Blob([snapshot.bytes]).stream().pipeThrough(redactor.stream())).arrayBuffer(),
      )
      if (redacted.equals(snapshot.bytes)) return false

      const candidate = join(dirname(path), `.typevault-redact-${randomUUID()}`)
      const file = await open(candidate, 'wx', 0o600)
      temporary = candidate
      try {
        await file.writeFile(redacted)
        await file.chmod(snapshot.mode)
        await file.sync()
      } finally {
        await file.close()
      }
      await rename(candidate, path)
      temporary = undefined
      return true
    } finally {
      if (temporary !== undefined) await rm(temporary, { force: true })
    }
  } catch (error) {
    throw new TypeVaultError(
      error instanceof TypeVaultError ? error.code : 'unavailable',
      `${path}: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
}
