import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, renameSync, writeSync } from 'node:fs'
import { basename, dirname, join, sep } from 'node:path'

import { randomHex } from './crypto'
import { utf8 } from './encoding'
import { TypeVaultError } from './errors'

export const ensureDir = (path: string, mode = 0o755): void => {
  mkdirSync(path, { recursive: true, mode })
}

export function fsyncDir(path: string): void {
  const fd = openSync(path, 'r')
  try {
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

/** Writes via a temp file in the same directory, fsync and rename: readers see the old or the new file, never a mix. */
export function atomicWrite(path: string, data: Uint8Array | string, mode = 0o644): void {
  const dir = dirname(path)
  ensureDir(dir)
  const temp = join(dir, `.${basename(path)}.${randomHex(6)}.tmp`)
  const fd = openSync(temp, 'wx', mode)
  try {
    writeSync(fd, typeof data === 'string' ? utf8(data) : data)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  renameSync(temp, path)
  fsyncDir(dir)
}

/**
 * Throws when any existing component of `rel` under `base` is a symlink. Vault directories come from git, and a
 * committed symlink must never steer a write or delete outside the vault.
 */
export function assertNoSymlinks(base: string, rel: string): void {
  let path = base
  for (const part of rel.split(sep).filter((segment) => segment !== '')) {
    path = join(path, part)
    // lstat, not exists: a dangling symlink reads as missing yet a write through it creates its target.
    const stat = lstatSync(path, { throwIfNoEntry: false })
    if (stat === undefined) return
    if (stat.isSymbolicLink()) throw new TypeVaultError('tampered', `${path} is a symlink`)
  }
}
