import { spawn } from 'node:child_process'
import { closeSync, existsSync, openSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { z } from 'zod'

import { machineKeys } from '../access/keys'
import { encodeSecretKey, type SecretKey } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { ensureDir } from '../core/fsx'
import { configDir, type Layout } from '../core/layout'
import { isLockHeld } from '../core/lock'
import { callDaemon, isDaemonAlive, servingPid } from './client'

type Env = Readonly<Record<string, string | undefined>>

const START_TIMEOUT_MS = 10_000
const POLL_MS = 50
const CLI = fileURLToPath(new URL('../cli/index.ts', import.meta.url))

export const LOCKED_MESSAGE = 'the vault is locked: ask a human to run `typevault unlock`'

/**
 * Starts the daemon in the background if it isn't running, like gpg-agent. Only a machine member can start one
 * unattended; a human's daemon is started by `typevault unlock`, so a locked vault stays locked.
 */
export async function ensureDaemon(layout: Layout, env: Env): Promise<void> {
  if (await isDaemonAlive(layout.agentSocket)) return
  if (machineKeys(env).length === 0) throw new TypeVaultError('locked', LOCKED_MESSAGE)
  await startBackground(layout, env, [process.execPath, CLI, 'daemon', 'run'])
}

/** Starts an unlocked session daemon holding `key`, handed over stdin so it never shows up in argv or env. */
export async function startSession(layout: Layout, env: Env, key: SecretKey, ttlMs: number): Promise<void> {
  const ttl = `${Math.ceil(ttlMs / 1000)}s`
  const command = [process.execPath, CLI, 'daemon', 'run', '--key-stdin', '--ttl', ttl]
  await startBackground(layout, env, command, encodeSecretKey(key))
}

/**
 * Stops this checkout's daemon and waits until it is gone, cleanup included: until it releases `run/daemon.lock`.
 * Only the process that answers on the checkout's socket is signaled, by the PID it reports itself, so a stale PID
 * file can never aim the signal at an unrelated process.
 */
export async function stopDaemon(layout: Layout): Promise<void> {
  const serving = await servingPid(layout.agentSocket)
  if (!isLockHeld(layout.daemonLock)) {
    const pidFile = join(layout.run, 'daemon.pid')
    if (serving !== undefined || (await isDaemonAlive(layout.agentSocket))) {
      // Something answers but holds no daemon lock: a daemon from an older release. It can't be identified safely.
      throw new TypeVaultError(
        'conflict',
        `a typevault daemon from an older release is running here; stop it (its PID is in ${pidFile}) and retry`,
      )
    }
    // No lock and no socket, yet the PID file names a live process: an older daemon still cleaning up, or an
    // unrelated process that reused a stale PID. Neither can be told apart safely, so nothing is signaled or replaced.
    const pid = pidIn(pidFile)
    if (pid !== undefined && isRunning(pid)) {
      throw new TypeVaultError(
        'conflict',
        `${pidFile} names a running process (pid ${pid}) that holds no daemon lock: if it is an older typevault daemon, wait for it to exit or stop it; if not, delete ${pidFile}`,
      )
    }
    throw new TypeVaultError('not_found', 'no daemon is running')
  }
  // With the lock held but no socket answering, the daemon is already shutting down: another signal would only cut
  // its cleanup short, so this just waits.
  if (serving !== undefined) await tellToStop(layout, serving)
  const deadline = Date.now() + STOP_TIMEOUT_MS
  while (isLockHeld(layout.daemonLock)) {
    if (Date.now() > deadline) {
      throw new TypeVaultError('unavailable', `the typevault daemon did not stop (${layout.daemonLock} is still held)`)
    }
    await Bun.sleep(POLL_MS)
  }
}

function pidIn(pidFile: string): number | undefined {
  if (!existsSync(pidFile)) return undefined
  const pid = Number.parseInt(readFileSync(pidFile, 'utf8'), 10)
  return Number.isInteger(pid) && pid > 0 ? pid : undefined
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

/**
 * SIGTERM on Unix. Windows has no catchable signal (process.kill terminates outright, skipping cleanup), so there the
 * daemon is asked over its control socket, which only this host's user reaches (sandboxes get the agent socket).
 */
async function tellToStop(layout: Layout, pid: number): Promise<void> {
  if (process.platform === 'win32') {
    try {
      await callDaemon(layout.controlSocket, '/v1/shutdown', {}, z.object({ ok: z.literal(true) }), {
        timeoutMs: 1_000,
      })
    } catch (error) {
      // It closed its socket since answering: it is already stopping.
      if (!(error instanceof TypeVaultError)) throw error
    }
    return
  }
  try {
    process.kill(pid, 'SIGTERM')
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ESRCH')) throw error
  }
}

const STOP_TIMEOUT_MS = 5_000

/**
 * Runs `command` detached as this checkout's daemon and waits until the agent socket answers. Exported for tests,
 * which stand in their own daemon.
 */
export async function startBackground(
  layout: Layout,
  env: Env,
  command: readonly string[],
  stdin?: string,
): Promise<void> {
  ensureDir(layout.run, 0o700)
  // A background daemon has no terminal: its output goes to a log, so a failed start can say why.
  const logPath = join(layout.run, 'daemon.log')
  const log = openSync(logPath, 'w', 0o600)
  // The child selects the same vault the way the CLI does: a project vault from its directory, the global one by path.
  // Its private state is where this process resolved it: `env` may lack the HOME this process fell back to.
  const childEnv = { ...env, XDG_CONFIG_HOME: dirname(configDir(env)) }
  const [executable = process.execPath, ...args] = command
  const child = spawn(executable, args, {
    detached: true,
    stdio: [stdin === undefined ? 'ignore' : 'pipe', log, log],
    ...(layout.scope === 'local'
      ? { cwd: dirname(layout.vault), env: childEnv }
      : { env: { ...childEnv, TYPEVAULT_DIR: layout.vault } }),
  })
  closeSync(log)
  if (stdin !== undefined) child.stdin?.end(stdin)
  child.unref()
  const deadline = Date.now() + START_TIMEOUT_MS
  while (Date.now() < deadline) {
    if (await isDaemonAlive(layout.agentSocket)) return
    // A daemon that dies on startup won't come up later, so its exit ends the wait, unless another start holds the
    // daemon lock: this child lost a race to it, and the winner may still be opening its vault before it serves.
    const exited = child.exitCode !== null || child.signalCode !== null
    if (exited && !isLockHeld(layout.daemonLock)) break
    await Bun.sleep(POLL_MS)
  }
  // Two starts racing: the one that loses exits with a conflict while the other's daemon is already serving.
  if (await isDaemonAlive(layout.agentSocket)) return
  throw new TypeVaultError('unavailable', `the typevault daemon did not start: ${whyNotStarted(logPath)}`)
}

/** The first line the daemon wrote before dying, with where to read the rest. */
function whyNotStarted(logPath: string): string {
  const first = existsSync(logPath)
    ? readFileSync(logPath, 'utf8')
        .split('\n')
        .map((line) => line.trim())
        .find((line) => line !== '')
    : undefined
  return first === undefined ? `no output (see ${logPath})` : `${first} (full log: ${logPath})`
}
