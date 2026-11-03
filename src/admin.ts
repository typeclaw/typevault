import { z } from 'zod'

import { adminCall, type Env } from './cli/context'

export const IssuedSchema = z.object({ token: z.string() })
export const GrantInfoSchema = z.object({
  id: z.string(),
  label: z.string(),
  tiers: z.array(z.string()),
  only: z.array(z.string()),
  exp: z.string(),
})
const RevokedSchema = z.object({ revoked: z.array(z.string()) })

export type GrantInfo = z.infer<typeof GrantInfoSchema>

export type GrantRequest = {
  readonly tiers: readonly string[]
  /** Names or globs the grant is narrowed to. Empty means everything in `tiers`. */
  readonly only?: readonly string[]
  /** e.g. `30m`, `1h`. Defaults to `1h`. */
  readonly ttl?: string
  /** Who this is for, e.g. `session:abc`. Shows up in the audit trail. */
  readonly label?: string
  /** An offline bundle: no daemon needed to read, no revocation. */
  readonly sealed?: boolean
}

export type AdminOptions = {
  /** A global-style typevault root. Defaults to `TYPEVAULT_DIR`; without one the vault is chosen like the CLI's. */
  readonly dir?: string
  /** Use the global vault instead of the project's, like the CLI's `-g`. Defaults to `TYPEVAULT_GLOBAL`. */
  readonly global?: boolean
  /** Which admin socket to use (`run/admin-<ceiling>.sock`). Defaults to `TYPEVAULT_CEILING`, else `default`. */
  readonly ceiling?: string
  /** Where the defaults above are read from. Defaults to `process.env`. */
  readonly env?: Env
}

export type AdminClient = {
  /** Issues a grant within this socket's ceiling and returns its token. */
  grant(request: GrantRequest): Promise<string>
  /** The grants this socket may see: all of them on an uncapped socket, its own otherwise. */
  list(): Promise<readonly GrantInfo[]>
  /** Revokes by id or label, along with grants derived from them. Returns the revoked ids. */
  revoke(target: { readonly id: string } | { readonly label: string }): Promise<readonly string[]>
}

/** Grant management over an admin socket, the same calls `typevault grant` makes. Starts the daemon if needed. */
export function createAdmin(options: AdminOptions = {}): AdminClient {
  const env: Env = {
    ...(options.env ?? process.env),
    ...(options.dir === undefined ? {} : { TYPEVAULT_DIR: options.dir }),
    ...(options.global === undefined ? {} : { TYPEVAULT_GLOBAL: options.global ? '1' : '' }),
    ...(options.ceiling === undefined ? {} : { TYPEVAULT_CEILING: options.ceiling }),
  }
  return {
    grant: async (request) => (await adminCall(env, '/v1/grant', request, IssuedSchema)).token,
    list: () => adminCall(env, '/v1/grants', {}, z.array(GrantInfoSchema)),
    revoke: async (target) => (await adminCall(env, '/v1/revoke', target, RevokedSchema)).revoked,
  }
}
