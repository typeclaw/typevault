import { TypeVaultError } from '../core/errors'
import {
  deriveEnvName,
  type EntryName,
  entryPattern,
  findField,
  hasRefScheme,
  isReservedEnvName,
  parseEntryRef,
  primaryField,
} from '../core/naming'
import { parseTotpSeed, totpCode } from '../otp/totp'
import type { EntryValue } from './types'

const isTotpField = (value: EntryValue, field: string): boolean =>
  (value.type === 'totp' && field === 'seed') || (value.type === 'password' && field === 'totp')

/**
 * Which entries `run` may put in a child's env. A lower group can write entries a higher one reads, so only the
 * runner's own groups load in bulk; an entry from an included group loads only when `--only` names it exactly.
 */
export type EnvPolicy = { readonly ownGroups: readonly string[]; readonly explicit: readonly string[] }

export const explicitNames = (only: readonly string[]): readonly string[] =>
  only.filter((pattern) => !/[*?[\]{}]/.test(pattern)).map(entryPattern)

export const envEligible = (value: EntryValue, policy: EnvPolicy): boolean =>
  policy.ownGroups.includes(value.group) || policy.explicit.includes(value.name)

/**
 * The environment `typevault run` gives a child: one variable per non-empty field, named by the entry's
 * `--env` override (primary field) or derived from the name. TOTP fields load the current code, never the seed.
 * Two entries producing the same variable is a conflict, never a silent override.
 */
export function envFor(values: readonly EntryValue[], now: Date, policy: EnvPolicy): Readonly<Record<string, string>> {
  const env: Record<string, string> = {}
  const owner = new Map<string, string>()
  for (const value of values.filter((candidate) => envEligible(candidate, policy))) {
    for (const [field, raw] of Object.entries(value.fields)) {
      if (raw === '') continue
      // An entry from an included group may pick its variable name only if its writer is at least as privileged
      // as the runner; otherwise it gets the derived name, so a lower writer can't aim it at OPENAI_BASE_URL.
      const ownOverride =
        value.env !== undefined &&
        field === primaryField(value.type) &&
        (policy.ownGroups.includes(value.group) || value.trustedWriter === true)
      const name = ownOverride && value.env !== undefined ? value.env : deriveEnvName(value.name, field)
      if (name === undefined || isReservedEnvName(name)) continue
      const previous = owner.get(name)
      if (previous !== undefined) throw new TypeVaultError('conflict', `${previous} and ${value.name} both set ${name}`)
      owner.set(name, value.name)
      env[name] = isTotpField(value, field) ? totpCode(parseTotpSeed(raw), now) : raw
    }
  }
  return env
}

export type ResolvedRefs = { readonly env: Readonly<Record<string, string>>; readonly values: readonly EntryValue[] }

/**
 * Replaces each variable whose whole value is a `tv://` reference (`FOO=tv://github/bot#password`) with the
 * referenced field, the primary one when none is named. The caller picked the variable, but a lower group can
 * still write the value, so loader variables are refused here as they are for entries.
 */
export async function resolveEnvRefs(
  env: Readonly<Record<string, string | undefined>>,
  get: (name: EntryName) => Promise<EntryValue>,
  now: Date,
): Promise<ResolvedRefs> {
  const resolved: Record<string, string> = {}
  const values: EntryValue[] = []
  for (const [variable, raw] of Object.entries(env)) {
    if (raw === undefined || !hasRefScheme(raw)) continue
    // Programs read some of these in lowercase too (curl's http_proxy), so the check ignores case.
    if (isReservedEnvName(variable.toUpperCase()))
      throw new TypeVaultError('invalid', `${variable} is reserved: run never sets it from the vault`)
    const ref = parseEntryRef(raw)
    const value = await get(ref.name)
    const wanted = ref.field ?? primaryField(value.type)
    const field = findField(value.fields, wanted)
    const secret = field === undefined ? undefined : value.fields[field]
    if (field === undefined || secret === undefined)
      throw new TypeVaultError('not_found', `${value.name} has no field "${wanted}"`)
    resolved[variable] = isTotpField(value, field) ? totpCode(parseTotpSeed(secret), now) : secret
    values.push(value)
  }
  return { env: resolved, values }
}

/** Secret values handed to the child: the injected env values plus TOTP seeds, for redaction. */
export const secretValues = (values: readonly EntryValue[]): readonly string[] =>
  values.flatMap((value) => Object.values(value.fields).filter((raw) => raw !== ''))
