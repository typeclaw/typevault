import { randomUUID } from 'node:crypto'
import { open, rename, rm } from 'node:fs/promises'
import { dirname, join } from 'node:path'

import { TypeVaultError } from '../core/errors'
import type { Redactor } from './index'

export async function scrubFile(path: string, redactor: Redactor): Promise<boolean> {
  let temporary: string | undefined
  try {
    try {
      const original = await open(path, 'r')
      const snapshot = await (async () => {
        try {
          return { text: await original.readFile('utf8'), mode: (await original.stat()).mode & 0o7777 }
        } finally {
          await original.close()
        }
      })()
      const redacted = redactor.redact(snapshot.text)
      if (redacted === snapshot.text) return false

      const candidate = join(dirname(path), `.typevault-redact-${randomUUID()}`)
      const file = await open(candidate, 'wx', 0o600)
      temporary = candidate
      try {
        await file.writeFile(redacted, 'utf8')
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
    if (error instanceof TypeVaultError) throw error
    throw new TypeVaultError('unavailable', 'Could not scrub file')
  }
}
