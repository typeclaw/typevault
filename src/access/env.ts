import { deriveEnvName, isReservedEnvName, primaryField } from '../core/naming'
import { parseTotpSeed, totpCode } from '../otp/totp'
import type { EntryValue } from './types'

const isTotpField = (value: EntryValue, field: string): boolean =>
  (value.type === 'totp' && field === 'seed') || (value.type === 'password' && field === 'totp')

/**
 * The environment `typevault run` gives a child: one variable per non-empty field, named by the entry's
 * `--env` override (primary field) or derived from the name. TOTP fields load the current code, never the seed.
 */
export function envFor(values: readonly EntryValue[], now: Date): Readonly<Record<string, string>> {
  const env: Record<string, string> = {}
  for (const value of values) {
    for (const [field, raw] of Object.entries(value.fields)) {
      if (raw === '') continue
      const name =
        value.env !== undefined && field === primaryField(value.type) ? value.env : deriveEnvName(value.name, field)
      if (isReservedEnvName(name)) continue
      env[name] = isTotpField(value, field) ? totpCode(parseTotpSeed(raw), now) : raw
    }
  }
  return env
}

/** Secret values handed to the child: the injected env values plus TOTP seeds, for redaction. */
export const secretValues = (values: readonly EntryValue[]): readonly string[] =>
  values.flatMap((value) => Object.values(value.fields).filter((raw) => raw !== ''))
