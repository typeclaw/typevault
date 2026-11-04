import { isUsableEnvName } from '../core/naming'
import { parseDotenvVariables } from './dotenv'
import { collectEntries } from './shared'
import type { ImportResult } from './types'

const PREFIX = 'TYPECLAW_SECRET_'

export function parseTypeclaw(text: string): ImportResult {
  return collectEntries(
    parseDotenvVariables(text)
      .filter(({ name }) => name.startsWith(PREFIX) && name.length > PREFIX.length)
      .map(({ name, value }) => ({
        title: name.slice(PREFIX.length),
        preset: 'api_key',
        fields: { $default: value },
        ...(isUsableEnvName(name) ? { env: name } : {}),
      })),
  )
}
