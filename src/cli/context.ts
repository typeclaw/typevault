import { z } from 'zod'

import { loadLocalKeys } from '../access/keys'
import { ScopedVault } from '../access/scoped'
import { readSealedGrant } from '../access/sealed'
import { SealedAccess } from '../access/sealed-access'
import type { Access } from '../access/types'
import { Admin } from '../core/admin'
import { TypeVaultError } from '../core/errors'
import { type Layout, layoutOf, resolveRoot } from '../core/layout'
import { Vault } from '../core/vault'
import { callDaemon } from '../daemon/client'
import { LiveAccess } from '../daemon/live-access'
import { ensureDaemon } from '../daemon/spawn'

export type Env = Readonly<Record<string, string | undefined>>

export const layoutFrom = (env: Env): Layout => layoutOf(resolveRoot(env))

/** The vault opened with this machine's own keys: direct mode, for the operator and launchers. */
export async function openDirect(env: Env): Promise<Vault> {
  const layout = layoutFrom(env)
  const keys = loadLocalKeys(layout, env)
  if (keys.length === 0) throw new TypeVaultError('denied', 'no grant and no key here (set TYPEVAULT_GRANT)')
  return Vault.open(layout.root, keys, env)
}

export const openAdmin = async (env: Env): Promise<Admin> => new Admin(await openDirect(env))

export type ResolvedAccess =
  | { readonly kind: 'live'; readonly access: LiveAccess }
  | { readonly kind: 'sealed'; readonly access: SealedAccess }
  | { readonly kind: 'direct'; readonly access: ScopedVault }

/** `TYPEVAULT_GRANT` decides: `tvl1.` live via the daemon, `tvg1:`/`@path` sealed, unset = direct mode. */
export async function resolveAccess(env: Env): Promise<ResolvedAccess> {
  const layout = layoutFrom(env)
  const grant = env['TYPEVAULT_GRANT']?.trim()
  if (grant === undefined || grant === '') {
    const group = env['TYPEVAULT_GROUP']
    const vault = await openDirect(env)
    return {
      kind: 'direct',
      access: new ScopedVault(vault, [], { mode: 'direct', ...(group === undefined ? {} : { defaultGroup: group }) }),
    }
  }
  if (grant.startsWith('tvl1.')) {
    await ensureDaemon(layout, env)
    return { kind: 'live', access: new LiveAccess(layout.agentSocket, grant) }
  }
  if (grant.startsWith('tvg1:') || grant.startsWith('@')) {
    return { kind: 'sealed', access: new SealedAccess(await readSealedGrant(grant), layout.root, env) }
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
