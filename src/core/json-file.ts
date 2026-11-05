import { readFileSync } from 'node:fs'

import { z } from 'zod'

import { TypeVaultError } from './errors'

/** Syntax and schema failures in persisted state are corruption, never request-body errors. */
export function readJsonFile<T>(path: string, schema: z.ZodType<T>): T {
  try {
    return schema.parse(JSON.parse(readFileSync(path, 'utf8')))
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof z.ZodError) {
      throw new TypeVaultError('tampered', `${path} is malformed; repair or restore this file before retrying`)
    }
    throw error
  }
}
