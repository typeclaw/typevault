import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { parse1Password } from './1password'
import { parseBitwarden } from './bitwarden'
import { parseCsv } from './csv'
import { parseDotenv } from './dotenv'
import { parseKeepass } from './keepass'
import { parseLastpass } from './lastpass'
import { parseExternal } from './shared'
import { parseTypeclaw } from './typeclaw'
import type { ImportResult, ImportSource } from './types'

export type { ImportedEntry, ImportResult, ImportSource } from './types'
export { ONEPASSWORD_VIAS, read1Password, type OnePasswordOptions, type OnePasswordVia } from './1password-live'

const SourceSchema = z.enum(['dotenv', 'typeclaw', '1password', 'bitwarden', 'lastpass', 'keepass', 'csv'])
const InputSchema = z.object({ path: z.string().min(1), password: z.string().optional() }).readonly()

export async function importFrom(
  source: ImportSource,
  input: { readonly path: string; readonly password?: string },
): Promise<ImportResult> {
  const format = parseExternal(source, SourceSchema, 'import source')
  const options = parseExternal(input, InputSchema, 'import input')
  if (format === 'keepass' && options.password === undefined) {
    throw new TypeVaultError('invalid', 'KeePass import requires a password')
  }
  let bytes: Uint8Array
  try {
    bytes = await readFile(format === 'typeclaw' ? join(options.path, '.env') : options.path)
  } catch (error) {
    if (error instanceof Error && 'code' in error) {
      if (error.code === 'ENOENT') throw new TypeVaultError('not_found', 'import source was not found')
      if (error.code === 'EACCES' || error.code === 'EPERM') {
        throw new TypeVaultError('denied', 'import source is not readable')
      }
      throw new TypeVaultError('invalid', 'could not read import source')
    }
    throw error
  }
  switch (format) {
    case '1password':
      return parse1Password(bytes)
    case 'keepass':
      return parseKeepass(bytes, options.password)
    case 'dotenv':
      return parseDotenv(new TextDecoder().decode(bytes))
    case 'typeclaw':
      return parseTypeclaw(new TextDecoder().decode(bytes))
    case 'bitwarden':
      return parseBitwarden(new TextDecoder().decode(bytes))
    case 'lastpass':
      return parseLastpass(new TextDecoder().decode(bytes))
    case 'csv':
      return parseCsv(new TextDecoder().decode(bytes))
    default:
      return assertNever(format)
  }
}

function assertNever(source: never): never {
  throw new TypeVaultError('invalid', `unknown import source: ${source}`)
}
