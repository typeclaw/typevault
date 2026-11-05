import { existsSync, rmSync, writeFileSync } from 'node:fs'
import { hostname } from 'node:os'

import { z } from 'zod'

import { randomHex } from './crypto'
import { TypeVaultError } from './errors'
import { readJsonFile } from './json-file'
import { hostId, type Layout } from './layout'

type Env = Readonly<Record<string, string | undefined>>

const CLAIM_ATTEMPTS = 3

const HolderSchema = z.object({
  host: z.string(),
  name: z.string(),
  pid: z.number().int(),
  token: z.string(),
  at: z.string(),
})
type Holder = z.infer<typeof HolderSchema>

export type DaemonClaim = {
  readonly release: () => void
  readonly owns: () => boolean
}

/**
 * flock does not cross machines (a bind mount between macOS and a Linux VM, say), so whoever runs a daemon (or
 * re-initializes the vault) also claims the state directory in `daemon.holder`, created exclusively. An opener on the
 * same machine trusts the flock; one on another machine refuses while any claim from another host is there. Another
 * machine's claim is never taken over: nothing here can tell a crashed daemon from a paused one, so a claim left by a
 * crash stays until someone who knows that daemon is gone deletes it.
 */
export function refuseForeignDaemon(layout: Layout, env: Env): void {
  const holder = readHolder(layout)
  if (holder !== undefined && holder.host !== hostId(env)) throw inUse(layout, holder)
}

/**
 * Claims the state directory for this process until `release`. The caller must hold `daemonLock`, so a claim this
 * machine left behind belongs to a daemon that is gone, and is replaced. Another machine's claim fails with `in_use`.
 */
export function claimDaemon(layout: Layout, env: Env): DaemonClaim {
  const token = randomHex(8)
  const record = JSON.stringify({
    host: hostId(env),
    name: hostname(),
    pid: process.pid,
    token,
    at: new Date().toISOString(),
  })
  for (let attempt = 0; ; attempt++) {
    try {
      writeFileSync(layout.daemonHolder, record, { flag: 'wx', mode: 0o600 })
      break
    } catch (error) {
      if (!isCode(error, 'EEXIST')) throw error
    }
    const holder = readHolder(layout)
    if (holder !== undefined && holder.host !== hostId(env)) throw inUse(layout, holder)
    if (attempt + 1 >= CLAIM_ATTEMPTS) {
      throw new TypeVaultError('in_use', `could not claim ${layout.root}: another process keeps claiming it`)
    }
    if (holder !== undefined) rmSync(layout.daemonHolder, { force: true })
  }
  const owns = (): boolean => readHolder(layout)?.token === token
  return {
    owns,
    release: () => {
      if (owns()) rmSync(layout.daemonHolder, { force: true })
    },
  }
}

function readHolder(layout: Layout): Holder | undefined {
  if (!existsSync(layout.daemonHolder)) return undefined
  try {
    return readJsonFile(layout.daemonHolder, HolderSchema)
  } catch (error) {
    if (isCode(error, 'ENOENT')) return undefined
    if (error instanceof TypeVaultError && error.code === 'tampered') {
      throw new TypeVaultError(
        'tampered',
        `${layout.daemonHolder} is malformed; if its daemon is gone for good, delete this file and retry`,
      )
    }
    throw error
  }
}

const inUse = (layout: Layout, holder: Holder): TypeVaultError =>
  new TypeVaultError(
    'in_use',
    `a typevault daemon on another machine (${holder.name}, pid ${holder.pid}, since ${holder.at}) is using ${layout.root}; one machine at a time may use a state directory (if that daemon is gone for good, delete ${layout.daemonHolder})`,
  )

const isCode = (error: unknown, code: string): boolean =>
  error instanceof Error && 'code' in error && error.code === code
