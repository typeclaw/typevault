import { z } from 'zod'

import { loadLocalKeys } from '../access/keys'
import { ScopedVault } from '../access/scoped'
import { readSealedGrant } from '../access/sealed'
import { SealedAccess } from '../access/sealed-access'
import type { Access } from '../access/types'
import { Admin } from '../core/admin'
import { TypeVaultError } from '../core/errors'
import { findLocalVault, type Layout, layoutOf, openLocalLayout, resolveRoot } from '../core/layout'
import { Vault } from '../core/vault'
import { callDaemon } from '../daemon/client'
import { LiveAccess } from '../daemon/live-access'
import { ensureDaemon } from '../daemon/spawn'

export type Env = Readonly<Record<string, string | undefined>>

const isSet = (value: string | undefined): boolean => value !== undefined && value !== ''

/** `-g` (`TYPEVAULT_GLOBAL`) or an explicit `TYPEVAULT_DIR` selects the global vault; otherwise the project's. */
export const wantsGlobal = (env: Env): boolean => isSet(env['TYPEVAULT_GLOBAL']) || isSet(env['TYPEVAULT_DIR'])

/** The selected vault, or undefined when no project vault is found from `cwd`. Never falls back to the global one. */
export function findLayout(env: Env, cwd: string = process.cwd()): Layout | undefined {
  if (wantsGlobal(env)) return layoutOf(resolveRoot(env))
  const dir = findLocalVault(cwd)
  return dir === undefined ? undefined : openLocalLayout(dir, env)
}

export function layoutFrom(env: Env, cwd: string = process.cwd()): Layout {
  const layout = findLayout(env, cwd)
  if (layout === undefined) {
    throw new TypeVaultError(
      'not_found',
      'no vault here (run `typevault init` to create one, or pass -g for the global vault)',
    )
  }
  return layout
}

/** The vault opened with this machine's own keys: direct mode, for the owner and issuers. */
export async function openDirect(env: Env): Promise<Vault> {
  const layout = layoutFrom(env)
  const keys = loadLocalKeys(layout, env)
  if (keys.length === 0) throw new TypeVaultError('denied', 'no grant and no key here (set TYPEVAULT_GRANT)')
  return Vault.open(layout, keys, env)
}

export const openAdmin = async (env: Env): Promise<Admin> => new Admin(await openDirect(env))

export type ResolvedAccess =
  | { readonly kind: 'live'; readonly access: LiveAccess }
  | { readonly kind: 'sealed'; readonly access: SealedAccess }
  | { readonly kind: 'direct'; readonly access: ScopedVault }

/** `TYPEVAULT_GRANT` decides: `tvl1.` live via the daemon, `tvg1:`/`@path` sealed, unset = direct mode. */
export async function resolveAccess(env: Env): Promise<ResolvedAccess> {
  const grant = env['TYPEVAULT_GRANT']?.trim()
  if (grant === undefined || grant === '') {
    const tier = env['TYPEVAULT_TIER']
    const vault = await openDirect(env)
    const ownTiers = vault.keys.flatMap((key) => (key.role.kind === 'tier' ? [key.role.tier] : []))
    const identity = { mode: 'direct' as const, ownTiers, ...(tier === undefined ? {} : { defaultTier: tier }) }
    return { kind: 'direct', access: new ScopedVault(vault, [], identity) }
  }
  if (grant.startsWith('tvl1.')) {
    const layout = layoutFrom(env)
    await ensureDaemon(layout, env)
    return { kind: 'live', access: new LiveAccess(layout.agentSocket, grant) }
  }
  if (grant.startsWith('tvg1:') || grant.startsWith('@')) {
    return { kind: 'sealed', access: new SealedAccess(await readSealedGrant(grant), findLayout(env), env) }
  }
  throw new TypeVaultError('invalid', 'TYPEVAULT_GRANT is not a typevault grant')
}

export const accessOf = async (env: Env): Promise<Access> => (await resolveAccess(env)).access

/** A call on this process's admin socket (`TYPEVAULT_CEILING`, default `default`), starting the daemon if needed. */
export async function adminCall<T>(env: Env, path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
  const layout = layoutFrom(env)
  await ensureDaemon(layout, env)
  return callDaemon(layout.adminSocket(env['TYPEVAULT_CEILING'] ?? 'default'), path, body, schema)
}
