import { spawn } from 'node:child_process'

import { TypeVaultError } from '../core/errors'
import type { Layout } from '../core/layout'
import { isDaemonAlive } from './client'

const START_TIMEOUT_MS = 10_000
const POLL_MS = 50
const CLI = new URL('../cli/index.ts', import.meta.url).pathname

/** Starts the daemon in the background if it isn't running, like gpg-agent. */
export async function ensureDaemon(layout: Layout, env: Readonly<Record<string, string | undefined>>): Promise<void> {
  if (await isDaemonAlive(layout.agentSocket)) return
  const child = spawn(process.execPath, [CLI, 'daemon', 'run'], {
    detached: true,
    stdio: 'ignore',
    env: { ...env, TYPEVAULT_DIR: layout.root },
  })
  child.unref()
  const deadline = Date.now() + START_TIMEOUT_MS
  while (Date.now() < deadline) {
    if (await isDaemonAlive(layout.agentSocket)) return
    await Bun.sleep(POLL_MS)
  }
  throw new TypeVaultError('unavailable', 'the typevault daemon did not start (run `typevault daemon run` to see why)')
}
