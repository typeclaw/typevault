import { chmodSync, existsSync, readdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { loadLocalKeys } from '../access/keys'
import { anchorAudit } from '../audit/log'
import { adoptCertWrites } from '../core/adopt'
import { TypeVaultError } from '../core/errors'
import { atomicWrite, ensureDir } from '../core/fsx'
import type { Layout } from '../core/layout'
import { Vault } from '../core/vault'
import { adminRoutes, type Ceiling } from './admin-routes'
import { agentRoutes, type DaemonContext } from './agent-routes'
import { isDaemonAlive } from './client'
import { GrantStore } from './grants'
import { router } from './http'
import { type PromptOptions, PromptRequests } from './requests'

const ADOPT_EVERY_MS = 60_000

export type DaemonOptions = {
  readonly layout: Layout
  readonly env: Readonly<Record<string, string | undefined>>
  readonly prompt?: PromptOptions
}
export type RunningDaemon = { readonly stop: () => Promise<void>; readonly ceilings: readonly Ceiling[] }

/** One admin socket per owner-signed ceiling, plus an uncapped `default` socket when this daemon holds the owner key. */
function ceilingsOf(vault: Vault): readonly Ceiling[] {
  const signed = Object.entries(vault.state.ceilings).map(([name, group]) => ({ name, group }))
  const owner = vault.keyring.owner !== undefined && vault.state.ceilings['default'] === undefined
  return owner ? [...signed, { name: 'default', group: '*' }] : signed
}

export async function startDaemon(options: DaemonOptions): Promise<RunningDaemon> {
  const { layout } = options
  ensureDir(layout.run, 0o700)
  if (await isDaemonAlive(layout.agentSocket))
    throw new TypeVaultError('conflict', 'a typevault daemon is already running')
  for (const file of readdirSync(layout.run).filter((name) => name.endsWith('.sock'))) rmSync(join(layout.run, file))
  const keys = loadLocalKeys(layout, options.env)
  if (keys.length === 0)
    throw new TypeVaultError('denied', 'the daemon has no keys (keys/ is empty and TYPEVAULT_KEY is unset)')
  const vault = await Vault.open(layout, keys, options.env)
  const ceilings = ceilingsOf(vault)
  if (ceilings.length === 0)
    throw new TypeVaultError('invalid', 'no ceilings configured (typevault ceiling set <name> <group>)')

  const context: DaemonContext = {
    vault,
    grants: new GrantStore(layout.grantsFile),
    sessions: new Map(),
    requests: new PromptRequests(vault, options.prompt ?? {}),
  }
  const listen = (path: string, fetch: (request: Request) => Promise<Response>) => {
    const server = Bun.serve({ unix: path, fetch, maxRequestBodySize: 1 << 20 })
    chmodSync(path, 0o600)
    return server
  }
  const servers = [
    listen(layout.agentSocket, router(agentRoutes(context))),
    ...ceilings.map((ceiling) => listen(layout.adminSocket(ceiling.name), router(adminRoutes(context, ceiling)))),
  ]
  atomicWrite(join(layout.run, 'daemon.pid'), String(process.pid), 0o600)
  const adopt = (): void => {
    adoptCertWrites(vault).then(undefined, (error: unknown) =>
      console.error('typevault daemon: adopting sealed writes failed', error),
    )
  }
  adopt()
  const adoption = setInterval(adopt, ADOPT_EVERY_MS)

  return {
    ceilings,
    stop: async () => {
      clearInterval(adoption)
      await Promise.all(servers.map((server) => server.stop(true)))
      await context.requests.stop()
      await anchorAudit(layout)
      for (const file of [
        layout.agentSocket,
        ...ceilings.map((c) => layout.adminSocket(c.name)),
        join(layout.run, 'daemon.pid'),
      ]) {
        if (existsSync(file)) rmSync(file)
      }
    },
  }
}
