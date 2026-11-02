import { defineCommand } from 'citty'
import { z } from 'zod'

import { envEligible, envFor, explicitNames, secretValues } from '../../access/env'
import { appendAudit } from '../../audit/log'
import { signerOf } from '../../core/entries'
import { TypeVaultError } from '../../core/errors'
import { importFrom, type ImportSource } from '../../import'
import { createRedactor, type Redactor, scrubFile } from '../../redact'
import { openDirect, resolveAccess } from '../context'
import { csv, note, print, readStdin } from '../output'

async function pump(stream: ReadableStream<Uint8Array>, redactor: Redactor, sink: NodeJS.WriteStream): Promise<void> {
  for await (const chunk of stream.pipeThrough(redactor.stream())) sink.write(chunk)
}

export const run = defineCommand({
  meta: { name: 'run', description: 'Run a command with secrets in its env; its output is redacted' },
  args: {
    only: { type: 'string', description: 'Comma-separated names or globs (default: everything you reach)' },
    reason: { type: 'string', description: 'Why (audited)' },
  },
  async run({ args, rawArgs }) {
    const dash = rawArgs.indexOf('--')
    const command = dash === -1 ? [] : rawArgs.slice(dash + 1)
    if (command.length === 0)
      throw new TypeVaultError('invalid', 'usage: typevault run [--only ...] -- <command> [args...]')
    const access = (await resolveAccess(process.env)).access
    const only = csv(args.only)
    const values = await access.values(only, args.reason)
    const policy = { ownGroups: await access.ownGroups(), explicit: explicitNames(only) }
    const env = envFor(values, new Date(), policy)
    const skipped = values.filter((value) => !envEligible(value, policy)).map((value) => value.name)
    if (skipped.length > 0) note(`not loaded (from included groups; name them in --only): ${skipped.join(', ')}`)
    const redactor = createRedactor([...secretValues(values), ...Object.values(env)])
    // The child gets its secrets, never the key or grant that opens the vault.
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('TYPEVAULT_')))
    const child = Bun.spawn(command, {
      env: { ...inherited, ...env },
      stdin: 'inherit',
      stdout: 'pipe',
      stderr: 'pipe',
    })
    await Promise.all([pump(child.stdout, redactor, process.stdout), pump(child.stderr, redactor, process.stderr)])
    process.exitCode = await child.exited
  },
})

async function redactorFor(): Promise<Redactor> {
  const resolved = await resolveAccess(process.env)
  // Direct mode has handed nothing out yet in this process, so it scrubs everything it can reach.
  const values =
    resolved.kind === 'direct'
      ? secretValues(await resolved.access.values([], 'redact'))
      : await resolved.access.readValues()
  return createRedactor(values)
}

export const redact = defineCommand({
  meta: { name: 'redact', description: 'Copy stdin to stdout with every secret your grant has read replaced' },
  async run() {
    const redactor = await redactorFor()
    await pump(Bun.stdin.stream(), redactor, process.stdout)
  },
})

export const scrub = defineCommand({
  meta: {
    name: 'scrub',
    description: 'Rewrite files (e.g. agent transcripts) with secrets your grant has read replaced',
  },
  args: { files: { type: 'positional', description: 'Files to scrub', required: true } },
  async run({ args, rawArgs }) {
    const redactor = await redactorFor()
    const files = rawArgs.filter((arg) => !arg.startsWith('-'))
    if (files.length === 0) throw new TypeVaultError('invalid', `usage: typevault scrub <file>... (got ${args.files})`)
    for (const file of files) if (await scrubFile(file, redactor)) print(file)
  },
})

const RequestResponse = z.object({ id: z.string(), url: z.string(), code: z.string() })

export const request = defineCommand({
  meta: { name: 'request', description: 'Ask a human for a secret through a one-time web page (live grants)' },
  args: {
    name: { type: 'positional', required: true },
    type: { type: 'string', required: true, description: 'Entry type' },
    group: { type: 'string', description: "Group (defaults to your grant's group)" },
    reason: { type: 'string', required: true, description: 'Shown to the human' },
  },
  async run({ args }) {
    const resolved = await resolveAccess(process.env)
    if (resolved.kind !== 'live')
      throw new TypeVaultError('unavailable', 'request needs a live grant (the daemon hosts the page)')
    const body = {
      name: args.name,
      type: args.type,
      reason: args.reason,
      ...(args.group === undefined ? {} : { group: args.group }),
    }
    const opened = await resolved.access.call('/v1/request', body, RequestResponse)
    print(`Send this link to the human: ${opened.url}\nMatch code: ${opened.code} (post it in the chat too)`)
    const done = await resolved.access.call(
      '/v1/request/wait',
      { id: opened.id },
      z.object({ stored: z.string() }),
      11 * 60_000,
    )
    print(`stored as ${done.stored}`)
  },
})

const SOURCES = ['dotenv', 'typeclaw', '1password', 'bitwarden', 'lastpass', 'keepass', 'csv'] as const
const isSource = (value: string): value is ImportSource => SOURCES.some((source) => source === value)

export const importCommand = defineCommand({
  meta: { name: 'import', description: 'Import a password-manager export into a group (operator, one transaction)' },
  args: {
    source: { type: 'positional', required: true, description: SOURCES.join(' | ') },
    path: { type: 'positional', required: true },
    group: { type: 'string', required: true },
    'password-stdin': { type: 'boolean', description: 'Read the KeePass password from stdin' },
  },
  async run({ args }) {
    if (!isSource(args.source)) throw new TypeVaultError('invalid', `source must be one of: ${SOURCES.join(', ')}`)
    const vault = await openDirect(process.env)
    const password = args['password-stdin'] ? await readStdin() : undefined
    const result = await importFrom(args.source, { path: args.path, ...(password === undefined ? {} : { password }) })
    const group = args.group
    const stored = await vault.putMany(
      result.entries.map((entry) => ({ ...entry, group })),
      async (target) => {
        const key = (await vault.keyring.unlock(target)) ?? vault.keyring.operator
        if (key === undefined) throw new TypeVaultError('denied', `no key here can write group "${target}"`)
        return signerOf(key)
      },
    )
    await appendAudit(vault.layout, {
      action: 'import',
      mode: 'direct',
      groups: [group],
      entries: stored.map((e) => e.payload.name),
    })
    for (const warning of result.warnings) note(`warning: ${warning}`)
    note(`imported ${stored.length} entries into ${group}`)
  },
})
