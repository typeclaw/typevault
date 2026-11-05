import { readFileSync } from 'node:fs'

import { z } from 'zod'

import { TypeVaultError } from './errors'

/** Syntax and schema failures in persisted state are corruption, never request-body errors. */
export function parseJsonText<T>(path: string, text: string, schema: z.ZodType<T>): T {
  try {
    return schema.parse(JSON.parse(text))
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof z.ZodError) {
      throw new TypeVaultError('tampered', `${path} is malformed; repair or restore this file before retrying`)
    }
    throw error
  }
}

export const readJsonFile = <T>(path: string, schema: z.ZodType<T>): T =>
  parseJsonText(path, readFileSync(path, 'utf8'), schema)
