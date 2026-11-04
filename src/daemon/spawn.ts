import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { z } from 'zod'

import { machineKeys } from '../access/keys'
import { encodeSecretKey, type SecretKey } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import type { Layout } from '../core/layout'
import { isDaemonAlive } from './client'

type Env = Readonly<Record<string, string | undefined>>

const START_TIMEOUT_MS = 10_000
const POLL_MS = 50
const CLI = new URL('../cli/index.ts', import.meta.url).pathname

export const LOCKED_MESSAGE = 'the vault is locked: ask a human to run `typevault unlock`'

/**
 * Starts the daemon in the background if it isn't running, like gpg-agent. Only a machine member can start one
 * unattended; a human's daemon is started by `typevault unlock`, so a locked vault stays locked.
 */
export async function ensureDaemon(layout: Layout, env: Env): Promise<void> {
  if (await isDaemonAlive(layout.agentSocket)) return
  if (machineKeys(env).length === 0) throw new TypeVaultError('locked', LOCKED_MESSAGE)
  await startBackground(layout, env, ['daemon', 'run'])
}

/** Starts an unlocked session daemon holding `key`, handed over stdin so it never shows up in argv or env. */
export async function startSession(layout: Layout, env: Env, key: SecretKey, ttlMs: number): Promise<void> {
  await startBackground(
    layout,
    env,
    ['daemon', 'run', '--key-stdin', '--ttl', `${Math.ceil(ttlMs / 1000)}s`],
    encodeSecretKey(key),
  )
}

/**
 * Stops the daemon and waits until its process has exited. Waiting for the socket to go quiet isn't enough: the
 * daemon removes its sockets and PID file last, and would delete a replacement's if one started in between.
 */
export async function stopDaemon(layout: Layout): Promise<void> {
  const pidFile = join(layout.run, 'daemon.pid')
  if (!existsSync(pidFile)) throw new TypeVaultError('not_found', 'no daemon is running')
  const pid = z.coerce.number().int().parse(readFileSync(pidFile, 'utf8'))
  if (!isRunning(pid)) return
  process.kill(pid, 'SIGTERM')
  const deadline = Date.now() + STOP_TIMEOUT_MS
  while (isRunning(pid)) {
    if (Date.now() > deadline) throw new TypeVaultError('unavailable', `the typevault daemon (pid ${pid}) did not stop`)
    await Bun.sleep(POLL_MS)
  }
}

function isRunning(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ESRCH') return false
    throw error
  }
}

const STOP_TIMEOUT_MS = 5_000

async function startBackground(layout: Layout, env: Env, args: readonly string[], stdin?: string): Promise<void> {
  // The child selects the same vault the way the CLI does: a project vault from its directory, the global one by root.
  const child = spawn(process.execPath, [CLI, ...args], {
    detached: true,
    stdio: [stdin === undefined ? 'ignore' : 'pipe', 'ignore', 'ignore'],
    ...(layout.scope === 'local'
      ? { cwd: dirname(layout.vault), env }
      : { env: { ...env, TYPEVAULT_DIR: layout.root } }),
  })
  if (stdin !== undefined) child.stdin?.end(stdin)
  child.unref()
  const deadline = Date.now() + START_TIMEOUT_MS
  while (Date.now() < deadline) {
    if (await isDaemonAlive(layout.agentSocket)) return
    await Bun.sleep(POLL_MS)
  }
  throw new TypeVaultError('unavailable', 'the typevault daemon did not start (run `typevault daemon run` to see why)')
}
