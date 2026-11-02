import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { isUsableEnvName } from '../core/naming'
import { collectEntries, parseExternal } from './shared'
import type { ImportResult } from './types'

const VariableSchema = z.object({ name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/), value: z.string() }).readonly()

export function parseDotenv(text: string): ImportResult {
  return collectEntries(
    parseDotenvVariables(text).map(({ name, value }) => ({
      title: name,
      type: 'api_key',
      fields: { key: value },
      ...(isUsableEnvName(name) ? { env: name } : {}),
    })),
  )
}

export function parseDotenvVariables(text: string): readonly z.infer<typeof VariableSchema>[] {
  const input = parseExternal(text, z.string(), 'dotenv')
    .replace(/^\uFEFF/, '')
    .replace(/\r\n?/g, '\n')
  const variables: { readonly name: string; readonly value: string }[] = []
  let offset = 0
  const invalid = () => new TypeVaultError('invalid', 'invalid dotenv assignment')
  while (offset < input.length) {
    const end = input.indexOf('\n', offset)
    const lineEnd = end < 0 ? input.length : end
    const line = input.slice(offset, lineEnd).trim()
    if (line === '' || line.startsWith('#')) {
      offset = lineEnd + 1
      continue
    }
    const assignment = /^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*/.exec(
      input.slice(offset, lineEnd).trimStart(),
    )
    const name = assignment?.[1]
    if (assignment === null || name === undefined) throw invalid()
    offset +=
      input.slice(offset, lineEnd).length - input.slice(offset, lineEnd).trimStart().length + assignment[0].length
    const quote = input[offset]
    let value = ''
    if (quote === "'" || quote === '"') {
      offset++
      let closed = false
      while (offset < input.length) {
        const char = input[offset++]
        if (char === quote) {
          closed = true
          break
        }
        if (quote === '"' && char === '\\') {
          const next = input[offset++]
          if (next === undefined) throw invalid()
          if (next === 'n') value += '\n'
          else if (next === 'r') value += '\r'
          else if (next === '"' || next === '\\') value += next
          else value += `\\${next}`
        } else value += char
      }
      if (!closed) throw invalid()
      const nextEnd = input.indexOf('\n', offset)
      const tailEnd = nextEnd < 0 ? input.length : nextEnd
      const tail = input.slice(offset, tailEnd).trim()
      if (tail !== '' && !tail.startsWith('#')) throw invalid()
      offset = tailEnd + 1
    } else {
      value = input.slice(offset, lineEnd).split('#')[0]?.trim() ?? ''
      offset = lineEnd + 1
    }
    variables.push({ name, value })
  }
  return parseExternal(variables, z.array(VariableSchema).readonly(), 'dotenv')
}
