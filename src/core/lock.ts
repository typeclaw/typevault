import { dlopen, FFIType, ptr } from 'bun:ffi'
import { AsyncLocalStorage } from 'node:async_hooks'
import { closeSync, openSync } from 'node:fs'
import { dirname } from 'node:path'

import { TypeVaultError } from './errors'
import { ensureDir } from './fsx'

const RETRY_MS = 10
const TIMEOUT_MS = 30_000

export type LockMode = 'shared' | 'exclusive'

/**
 * An advisory whole-file lock the OS drops when its holder exits, however it exits: flock on Unix, LockFileEx on
 * Windows. Each open handle locks on its own, so two handles in one process conflict like two processes would.
 */
type FileLocks = {
  /** Opens `path` for locking, creating it unless `existing`; undefined when `existing` and it isn't there. */
  readonly open: (path: string, existing: boolean) => number | undefined
  readonly tryLock: (handle: number, mode: LockMode) => boolean
  readonly unlock: (handle: number) => void
  readonly close: (handle: number) => void
}

function posixLocks(): FileLocks {
  const LOCK_SH = 1
  const LOCK_EX = 2
  const LOCK_NB = 4
  const LOCK_UN = 8
  const libc = dlopen(process.platform === 'darwin' ? '/usr/lib/libSystem.B.dylib' : 'libc.so.6', {
    flock: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
  })
  return {
    open: (path, existing) => {
      try {
        return openSync(path, existing ? 'r' : 'a', 0o600)
      } catch (error) {
        if (existing && error instanceof Error && 'code' in error && error.code === 'ENOENT') return undefined
        throw error
      }
    },
    tryLock: (fd, mode) => libc.symbols.flock(fd, (mode === 'exclusive' ? LOCK_EX : LOCK_SH) | LOCK_NB) === 0,
    unlock: (fd) => void libc.symbols.flock(fd, LOCK_UN),
    close: closeSync,
  }
}

function windowsLocks(): FileLocks {
  const GENERIC_READ_WRITE = 0xc0000000
  const FILE_SHARE_ALL = 0x7 // read | write | delete: the lock, not the open, is what excludes
  const OPEN_EXISTING = 3
  const OPEN_ALWAYS = 4
  const FILE_ATTRIBUTE_NORMAL = 0x80
  const INVALID_HANDLE_VALUE = -1
  const LOCKFILE_FAIL_IMMEDIATELY = 0x1
  const LOCKFILE_EXCLUSIVE_LOCK = 0x2
  const ERROR_FILE_NOT_FOUND = 2
  const ERROR_PATH_NOT_FOUND = 3
  const handle = FFIType.i64_fast
  const kernel32 = dlopen('kernel32.dll', {
    CreateFileW: {
      args: [FFIType.ptr, FFIType.u32, FFIType.u32, FFIType.ptr, FFIType.u32, FFIType.u32, handle],
      returns: handle,
    },
    LockFileEx: {
      args: [handle, FFIType.u32, FFIType.u32, FFIType.u32, FFIType.u32, FFIType.ptr],
      returns: FFIType.i32,
    },
    UnlockFileEx: { args: [handle, FFIType.u32, FFIType.u32, FFIType.u32, FFIType.ptr], returns: FFIType.i32 },
    CloseHandle: { args: [handle], returns: FFIType.i32 },
    GetLastError: { args: [], returns: FFIType.u32 },
  })
  const { CreateFileW, LockFileEx, UnlockFileEx, CloseHandle, GetLastError } = kernel32.symbols
  // A zeroed OVERLAPPED (32 bytes on 64-bit): the locked range starts at offset 0. One byte stands for the whole file.
  const overlapped = () => ptr(new Uint8Array(32))
  return {
    open: (path, existing) => {
      const wide = Buffer.from(`${path}\0`, 'utf16le')
      const disposition = existing ? OPEN_EXISTING : OPEN_ALWAYS
      const h = Number(
        CreateFileW(ptr(wide), GENERIC_READ_WRITE, FILE_SHARE_ALL, null, disposition, FILE_ATTRIBUTE_NORMAL, 0),
      )
      if (h !== INVALID_HANDLE_VALUE) return h
      const code = GetLastError()
      if (existing && (code === ERROR_FILE_NOT_FOUND || code === ERROR_PATH_NOT_FOUND)) return undefined
      throw new TypeVaultError('unavailable', `cannot open the lock file ${path} (Windows error ${code})`)
    },
    tryLock: (h, mode) => {
      const flags = LOCKFILE_FAIL_IMMEDIATELY | (mode === 'exclusive' ? LOCKFILE_EXCLUSIVE_LOCK : 0)
      return LockFileEx(h, flags, 0, 1, 0, overlapped()) !== 0
    },
    unlock: (h) => void UnlockFileEx(h, 0, 1, 0, overlapped()),
    close: (h) => void CloseHandle(h),
  }
}

const locks = process.platform === 'win32' ? windowsLocks() : posixLocks()

/** Locks held by the current async call chain, so nested calls re-enter instead of deadlocking. */
const owned = new AsyncLocalStorage<ReadonlyMap<string, LockMode>>()
/** In-process queue per lock file: flock alone can't separate two concurrent requests in one daemon. */
const tails = new Map<string, Promise<void>>()

function openForLock(path: string): number {
  ensureDir(dirname(path), 0o700)
  const handle = locks.open(path, false)
  if (handle === undefined) throw new TypeVaultError('unavailable', `cannot open the lock file ${path}`)
  return handle
}

async function acquire(path: string, mode: LockMode): Promise<number> {
  const fd = openForLock(path)
  const deadline = Date.now() + TIMEOUT_MS
  while (!locks.tryLock(fd, mode)) {
    if (Date.now() > deadline) {
      locks.close(fd)
      throw new TypeVaultError('locked', `timed out waiting for the vault lock at ${path}`)
    }
    await Bun.sleep(RETRY_MS)
  }
  return fd
}

/**
 * Takes an exclusive flock on `path` without waiting, and returns its release, or undefined when another holder has
 * it. Held for as long as the holder lives: the kernel drops it when the process exits, however it exits.
 */
export function holdLock(path: string): (() => void) | undefined {
  const fd = openForLock(path)
  if (!locks.tryLock(fd, 'exclusive')) {
    locks.close(fd)
    return undefined
  }
  return () => {
    locks.unlock(fd)
    locks.close(fd)
  }
}

/** Whether some holder has `path` locked right now. A lock that can't be tested counts as held. */
export function isLockHeld(path: string): boolean {
  const fd = locks.open(path, true)
  if (fd === undefined) return false
  try {
    if (!locks.tryLock(fd, 'exclusive')) return true
    locks.unlock(fd)
    return false
  } finally {
    locks.close(fd)
  }
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
      locks.unlock(fd)
      locks.close(fd)
    }
  } finally {
    release()
    if (tails.get(path) === tail) tails.delete(path)
  }
}
