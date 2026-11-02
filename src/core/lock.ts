import { dlopen, FFIType } from 'bun:ffi'
import { AsyncLocalStorage } from 'node:async_hooks'
import { closeSync, openSync } from 'node:fs'
import { dirname } from 'node:path'

import { TypeVaultError } from './errors'
import { ensureDir } from './fsx'

const LOCK_SH = 1
const LOCK_EX = 2
const LOCK_NB = 4
const LOCK_UN = 8
const RETRY_MS = 10
const TIMEOUT_MS = 30_000

const libc = dlopen(process.platform === 'darwin' ? '/usr/lib/libSystem.B.dylib' : 'libc.so.6', {
  flock: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
})

export type LockMode = 'shared' | 'exclusive'

/** Locks held by the current async call chain, so nested calls re-enter instead of deadlocking. */
const owned = new AsyncLocalStorage<ReadonlyMap<string, LockMode>>()
/** In-process queue per lock file: flock alone can't separate two concurrent requests in one daemon. */
const tails = new Map<string, Promise<void>>()

async function acquire(path: string, mode: LockMode): Promise<number> {
  ensureDir(dirname(path), 0o700)
  const fd = openSync(path, 'a', 0o600)
  const operation = (mode === 'exclusive' ? LOCK_EX : LOCK_SH) | LOCK_NB
  const deadline = Date.now() + TIMEOUT_MS
  while (libc.symbols.flock(fd, operation) !== 0) {
    if (Date.now() > deadline) {
      closeSync(fd)
      throw new TypeVaultError('locked', `timed out waiting for the vault lock at ${path}`)
    }
    await Bun.sleep(RETRY_MS)
  }
  return fd
}

/**
 * Runs `fn` under a cross-process flock: shared for readers, exclusive for writers.
 * Within one process, callers are serialized. The kernel drops the lock if the process dies,
 * so a crash never leaves the vault locked.
 */
export async function withLock<T>(path: string, mode: LockMode, fn: () => Promise<T>): Promise<T> {
  const mine = owned.getStore()
  const heldMode = mine?.get(path)
  if (heldMode !== undefined) {
    if (mode === 'exclusive' && heldMode === 'shared') {
      throw new TypeVaultError('locked', 'cannot upgrade a shared vault lock to exclusive')
    }
    return fn()
  }
  const previous = tails.get(path) ?? Promise.resolve()
  const { promise: released, resolve: release } = Promise.withResolvers<void>()
  const tail = previous.then(() => released)
  tails.set(path, tail)
  await previous
  try {
    const fd = await acquire(path, mode)
    try {
      return await owned.run(new Map([...(mine ?? []), [path, mode]]), fn)
    } finally {
      libc.symbols.flock(fd, LOCK_UN)
      closeSync(fd)
    }
  } finally {
    release()
    if (tails.get(path) === tail) tails.delete(path)
  }
}
