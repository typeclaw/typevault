import { spawn } from 'node:child_process'
import { dirname } from 'node:path'

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
