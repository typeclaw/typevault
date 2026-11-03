import { spawn } from 'node:child_process'
import { dirname } from 'node:path'

import { TypeVaultError } from '../core/errors'
import type { Layout } from '../core/layout'
import { isDaemonAlive } from './client'

const START_TIMEOUT_MS = 10_000
const POLL_MS = 50
const CLI = new URL('../cli/index.ts', import.meta.url).pathname

/** Starts the daemon in the background if it isn't running, like gpg-agent. */
export async function ensureDaemon(layout: Layout, env: Readonly<Record<string, string | undefined>>): Promise<void> {
  if (await isDaemonAlive(layout.agentSocket)) return
  // The child selects the same vault the way the CLI does: a project vault from its directory, the global one by root.
  const child = spawn(process.execPath, [CLI, 'daemon', 'run'], {
    detached: true,
    stdio: 'ignore',
    ...(layout.scope === 'local'
      ? { cwd: dirname(layout.vault), env }
      : { env: { ...env, TYPEVAULT_DIR: layout.root } }),
  })
  child.unref()
  const deadline = Date.now() + START_TIMEOUT_MS
  while (Date.now() < deadline) {
    if (await isDaemonAlive(layout.agentSocket)) return
    await Bun.sleep(POLL_MS)
  }
  throw new TypeVaultError('unavailable', 'the typevault daemon did not start (run `typevault daemon run` to see why)')
}
