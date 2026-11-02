import { describe, expect, it } from 'bun:test'
import { chmod, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { TypeVaultError } from '../core/errors'
import { createRedactor, scrubFile } from './index'

describe('scrubFile', () => {
  it('atomically replaces changed content and preserves the original mode', async () => {
    // Given
    const directory = await mkdtemp(join(tmpdir(), 'typevault-redact-'))
    try {
      const path = join(directory, 'transcript.txt')
      await writeFile(path, 'before secret-value after')
      await chmod(path, 0o640)
      const original = await stat(path)
      // When
      const changed = await scrubFile(path, createRedactor(['secret-value']))
      // Then
      const current = await stat(path)
      expect(changed).toBe(true)
      expect(await readFile(path, 'utf8')).toBe('before [redacted] after')
      expect(current.mode & 0o7777).toBe(0o640)
      expect(current.ino).not.toBe(original.ino)
      expect(await readdir(directory)).toEqual(['transcript.txt'])
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })

  it('leaves the file untouched when no values match', async () => {
    // Given
    const directory = await mkdtemp(join(tmpdir(), 'typevault-redact-'))
    try {
      const path = join(directory, 'transcript.txt')
      await writeFile(path, 'ordinary text')
      await chmod(path, 0o400)
      const original = await stat(path)
      // When
      const changed = await scrubFile(path, createRedactor(['secret-value']))
      // Then
      const current = await stat(path)
      expect(changed).toBe(false)
      expect(await readFile(path, 'utf8')).toBe('ordinary text')
      expect(current.ino).toBe(original.ino)
      expect(current.mtimeMs).toBe(original.mtimeMs)
      expect(current.ctimeMs).toBe(original.ctimeMs)
      expect(current.mode & 0o7777).toBe(0o400)
      expect(await readdir(directory)).toEqual(['transcript.txt'])
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })

  it('reports missing files as typed errors', async () => {
    // Given
    const directory = await mkdtemp(join(tmpdir(), 'typevault-redact-'))
    try {
      const path = join(directory, 'missing.txt')
      // When / Then
      await expect(scrubFile(path, createRedactor(['secret-value']))).rejects.toBeInstanceOf(TypeVaultError)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
})
