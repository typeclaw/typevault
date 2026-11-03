import type { Access } from './access/types'
import { type Env, resolveAccess } from './cli/context'
import { TypeVaultError } from './core/errors'

export type { Access, EntrySummary, EntryValue, SetInput } from './access/types'
export { type ErrorCode, TypeVaultError } from './core/errors'
export {
  type EntryName,
  type EntryRef,
  type EntryType,
  fieldsOf,
  parseEntryName,
  parseEntryRef,
  parseEntryType,
  primaryField,
} from './core/naming'

export type ClientOptions = {
  /** A live (`tvl1.…`), sealed (`tvg1:…`) or `@path` grant. Defaults to `TYPEVAULT_GRANT`. */
  readonly grant?: string
  /** A global-style typevault root. Defaults to `TYPEVAULT_DIR`; without one the vault is chosen like the CLI's. */
  readonly dir?: string
  /** Without a grant, open the vault with this machine's own keys (operator, launchers). Off by default. */
  readonly direct?: boolean
  /** Where the defaults above are read from. Defaults to `process.env`. */
  readonly env?: Env
}

/**
 * The same access the CLI has: a live grant goes through the daemon (started if needed), a sealed grant is read
 * in-process. Values returned here are not redacted anywhere: pass `readValues()` to `typevault/redact` if they
 * can reach output.
 */
export async function createClient(options: ClientOptions = {}): Promise<Access> {
  const base = options.env ?? process.env
  const grant = (options.grant ?? base['TYPEVAULT_GRANT'])?.trim()
  if ((grant === undefined || grant === '') && options.direct !== true) {
    throw new TypeVaultError('denied', 'no grant given (pass `grant`, set TYPEVAULT_GRANT, or opt into `direct`)')
  }
  const env: Env = {
    ...base,
    TYPEVAULT_GRANT: grant,
    ...(options.dir === undefined ? {} : { TYPEVAULT_DIR: options.dir }),
  }
  return (await resolveAccess(env)).access
}
