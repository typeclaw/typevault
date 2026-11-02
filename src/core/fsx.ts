import { closeSync, fsyncSync, mkdirSync, openSync, renameSync, writeSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'

import { randomHex } from './crypto'
import { utf8 } from './encoding'

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
