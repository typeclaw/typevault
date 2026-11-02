#!/usr/bin/env bun
import { defineCommand, runCommand, runMain } from 'citty'

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

const rawArgs = process.argv.slice(2)
const ownArgs = rawArgs.includes('--') ? rawArgs.slice(0, rawArgs.indexOf('--')) : rawArgs
const wantsUsage = ownArgs.length === 0 || ownArgs.some((arg) => arg === '--help' || arg === '-h')

if (wantsUsage) {
  await runMain(main)
} else {
  try {
    // no-excuse-ok: catch (top-level CLI boundary turns typed errors into a one-line message)
    await runCommand(main, { rawArgs })
  } catch (error) {
    if (error instanceof TypeVaultError) {
      process.stderr.write(`typevault: ${error.message}\n`)
      process.exit(1)
    }
    // citty's usage errors (unknown command, missing argument): its own runner prints usage for them.
    if (error instanceof Error && error.name === 'CLIError') await runMain(main)
    else throw error
  }
}
