import { TypeVaultError } from '../core/errors'
import {
  deriveEnvName,
  type EntryName,
  entryPattern,
  defaultField,
  defaultFieldOf,
  type Field,
  fieldValue,
  fieldStrings,
  resolveField,
  hasRefScheme,
  isReservedEnvName,
  parseEntryRef,
} from '../core/naming'
import { parseTotpSeed, totpCode } from '../otp/totp'
import type { EntryValue } from './types'

/**
 * Which entries `run` may put in a child's env. A lower tier can write entries a higher one reads, so only the
 * runner's own tiers load in bulk; an entry from an included tier loads only when `--only` names it exactly.
 */
export type EnvPolicy = { readonly ownTiers: readonly string[]; readonly explicit: readonly string[] }

export const explicitNames = (only: readonly string[]): readonly string[] =>
  only.filter((pattern) => !/[*?[\]{}]/.test(pattern)).map(entryPattern)

export const envEligible = (value: EntryValue, policy: EnvPolicy): boolean =>
  policy.ownTiers.includes(value.tier) || policy.explicit.includes(value.name)

/**
 * The environment `typevault run` gives a child: one variable per non-empty field, named by the entry's
 * `--env` override (default field) or derived from the name. TOTP fields load the current code, never the seed.
 * Two entries producing the same variable is a conflict, never a silent override.
 */
export function envFor(values: readonly EntryValue[], now: Date, policy: EnvPolicy): Readonly<Record<string, string>> {
  const env: Record<string, string> = {}
  const owner = new Map<string, string>()
  for (const value of values.filter((candidate) => envEligible(candidate, policy))) {
    for (const [field, raw] of Object.entries(value.fields)) {
      if (fieldValue(raw) === '') continue
      // An entry from an included tier may pick its variable name only if its writer is at least as privileged
      // as the runner; otherwise it gets the derived name, so a lower writer can't aim it at OPENAI_BASE_URL.
      const ownOverride =
        value.env !== undefined &&
        (policy.ownTiers.includes(value.tier) || value.trustedWriter === true) &&
        field === defaultFieldOf(value.fields)
      const name = ownOverride && value.env !== undefined ? value.env : deriveEnvName(value.name, field)
      if (name === undefined || isReservedEnvName(name)) continue
      const previous = owner.get(name)
      if (previous !== undefined) throw new TypeVaultError('conflict', `${previous} and ${value.name} both set ${name}`)
      owner.set(name, value.name)
      env[name] = readField(raw, now)
    }
  }
  return env
}

export type ResolvedRefs = { readonly env: Readonly<Record<string, string>>; readonly values: readonly EntryValue[] }

/**
 * Replaces each variable whose whole value is a `tv://` reference (`FOO=tv://github/bot#password`) with the
 * referenced field, the default one when none is named. The caller picked the variable, but a lower tier can
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
    const wanted = ref.field ?? defaultField(value.fields, value.name)
    const secret = resolveField(value.fields, wanted)
    if (secret === undefined) throw new TypeVaultError('not_found', `${value.name} has no field "${wanted}"`)
    resolved[variable] = readField(secret, now)
    values.push(value)
  }
  return { env: resolved, values }
}

/** Secret values handed to the child: the injected env values plus TOTP seeds, for redaction. */
export const secretValues = (values: readonly EntryValue[]): readonly string[] =>
  values.flatMap((value) =>
    Object.values(value.fields)
      .flatMap(fieldStrings)
      .filter((raw) => raw !== ''),
  )

function readField(field: Field, now: Date): string {
  switch (field.type) {
    case 'totp':
      return totpCode(parseTotpSeed(field.value), now)
    case 'secret':
    case 'text':
    case 'oauth':
      return fieldValue(field)
    default:
      return assertNever(field)
  }
}
function assertNever(value: never): never {
  throw new TypeVaultError('invalid', `unexpected field ${JSON.stringify(value)}`)
}
