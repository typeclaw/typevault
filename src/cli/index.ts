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
  args: {
    global: { type: 'boolean', alias: 'g', description: 'Use the global vault instead of the project vault' },
  },
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

const argv = process.argv.slice(2)
const split = argv.includes('--') ? argv.indexOf('--') : argv.length
const isGlobalFlag = (arg: string): boolean => arg === '-g' || arg === '--global'
// -g applies to every command, so it is taken out here; anything after `--` belongs to the child of `run`.
if (argv.slice(0, split).some(isGlobalFlag)) process.env['TYPEVAULT_GLOBAL'] = '1'
const ownArgs = argv.slice(0, split).filter((arg) => !isGlobalFlag(arg))
const rawArgs = [...ownArgs, ...argv.slice(split)]
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
