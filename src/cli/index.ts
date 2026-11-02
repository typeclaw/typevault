#!/usr/bin/env bun
import { defineCommand, runMain } from 'citty'

import { TypeVaultError } from '../core/errors'
import { ceiling, doctor, group, init, key, signer } from './commands/admin'
import { daemon } from './commands/daemon'
import { get, ls, mv, otp, rm, set, whoami } from './commands/entries'
import { audit, grant } from './commands/grant'
import { importCommand, redact, request, run, scrub } from './commands/run'

const main = defineCommand({
  meta: { name: 'typevault', description: 'A CLI-first secrets vault for agents' },
  subCommands: {
    init,
    group,
    ceiling,
    signer,
    key,
    daemon,
    grant,
    audit,
    doctor,
    ls,
    get,
    set,
    rm,
    mv,
    otp,
    run,
    redact,
    scrub,
    request,
    import: importCommand,
    whoami,
  },
})

try {
  // no-excuse-ok: catch (top-level CLI boundary turns typed errors into a one-line message)
  await runMain(main)
} catch (error) {
  if (!(error instanceof TypeVaultError)) throw error
  process.stderr.write(`typevault: ${error.message}\n`)
  process.exit(1)
}
