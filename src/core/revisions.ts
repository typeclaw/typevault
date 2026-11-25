import { existsSync } from 'node:fs'

import { z } from 'zod'

import { atomicWrite } from './fsx'
import { readJsonFile } from './json-file'
import { RevisionLedger } from './revision-ledger'

const MarksSchema = z.record(z.string(), z.number().int())

/** A {@link RevisionLedger} kept in a file on this machine. */
export class RevisionMarks extends RevisionLedger {
  readonly #path: string

  constructor(path: string) {
    super(existsSync(path) ? readJsonFile(path, MarksSchema) : {})
    this.#path = path
  }

  save(): void {
    if (!this.dirty) return
    atomicWrite(this.#path, JSON.stringify(this.snapshot()), 0o600)
    this.saved()
  }
}
