import { pipeline } from 'node:stream/promises'

import { defineCommand } from 'citty'
import { z } from 'zod'

import { envEligible, envFor, explicitNames, resolveEnvRefs, secretValues } from '../../access/env'
import { TypeVaultError } from '../../core/errors'
import { ENTRY_NAME_SYNTAX, matchesOnly } from '../../core/naming'
import { importFrom, ONEPASSWORD_VIAS, type ImportSource, type OnePasswordVia, read1Password } from '../../import'
import { createRedactor, type Redactor, scrubFile } from '../../redact'
import { getEntry, inGlobalVault, resolveAccess } from '../context'
import { csv, note, print, readStdin, repeated } from '../output'

async function pump(
  stream: ReadableStream<Uint8Array>,
  redactor: Redactor,
  sink: NodeJS.WriteStream,
  onClosed: () => void = () => {},
): Promise<void> {
  const isClosed = (error: unknown): boolean =>
    error instanceof Error && 'code' in error && (error.code === 'EPIPE' || error.code === 'ENOTCONN')
  const onError = (error: Error) => {
    if (isClosed(error)) onClosed()
  }
  sink.on('error', onError)
  try {
    await pipeline(stream.pipeThrough(redactor.stream()), sink, { end: false })
  } catch (error) {
    if (!isClosed(error)) throw error
  } finally {
    sink.off('error', onError)
  }
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
    const only = repeated(rawArgs.slice(0, dash), '--only').flatMap(csv)
    const values = await access.values(only, args.reason)
    const unmatched = only.filter((pattern) => !values.some((value) => matchesOnly(value.name, [pattern])))
    if (unmatched.length > 0) note(`warning: --only matched no entries: ${unmatched.join(', ')}`)
    const inGlobal = await inGlobalVault(process.env, explicitNames(unmatched))
    if (inGlobal.length > 0) note(`the global vault has ${inGlobal.join(', ')}: rerun with -g`)
    const policy = { ownTiers: await access.ownTiers(), explicit: explicitNames(only) }
    const env = envFor(values, new Date(), policy)
    // The child gets its secrets, never the key or grant that opens the vault.
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('TYPEVAULT_')))
    const refs = await resolveEnvRefs(inherited, (name) => getEntry(access, name, args.reason), new Date())
    const referenced = new Set(refs.values.map((value) => value.name))
    const skipped = values
      .filter((value) => !envEligible(value, policy) && !referenced.has(value.name))
      .map((value) => value.name)
    if (skipped.length > 0) note(`not loaded (from included tiers; name them in --only): ${skipped.join(', ')}`)
    const clash = Object.keys(refs.env).find((name) => Object.hasOwn(env, name))
    if (clash !== undefined)
      throw new TypeVaultError('conflict', `${clash} is both a typevault:// reference and an entry's variable`)
    const redactor = createRedactor([
      ...secretValues([...values, ...refs.values]),
      ...Object.values(env),
      ...Object.values(refs.env),
    ])
    const child = (() => {
      try {
        return Bun.spawn(command, {
          env: { ...inherited, ...env, ...refs.env },
          // Own the group so descendants receive forwarded signals, and terminal Ctrl-C reaches them only once.
          detached: process.platform !== 'win32',
          stdin: 'inherit',
          stdout: 'pipe',
          stderr: 'pipe',
        })
      } catch (error) {
        if (error instanceof Error && 'code' in error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
          note(error.message)
          return error.code === 'ENOENT' ? 127 : 126
        }
        throw error
      }
    })()
    if (typeof child === 'number') {
      process.exitCode = child
      return
    }
    const signals = ['SIGTERM', 'SIGINT', 'SIGHUP'] as const
    const forward = (signal: NodeJS.Signals): void => {
      if (process.platform === 'win32') {
        child.kill(signal)
        return
      }
      try {
        process.kill(-child.pid, signal)
      } catch (error) {
        // The group may have exited before its exit notification was handled.
        if (!(error instanceof Error && 'code' in error && error.code === 'ESRCH')) throw error
      }
    }
    // A closed reader must not leave the child or its descendants blocked on their output pipes.
    const onClosed = () => forward('SIGKILL')
    for (const signal of signals) process.on(signal, forward)
    try {
      const [code] = await Promise.all([
        child.exited,
        pump(child.stdout, redactor, process.stdout, onClosed),
        pump(child.stderr, redactor, process.stderr, onClosed),
      ])
      process.exitCode = code
    } finally {
      for (const signal of signals) process.off(signal, forward)
    }
  },
})

async function redactorFor(): Promise<Redactor> {
  const resolved = await resolveAccess(process.env)
  // Direct mode has handed nothing out yet in this process, so it scrubs everything it can reach.
  const values =
    resolved.kind === 'direct'
      ? secretValues(await resolved.access.values([], 'redact'))
      : await resolved.access.readValues()
  if (!values.some((value) => Array.from(value).length >= 4)) {
    throw new TypeVaultError(
      'unavailable',
      'No redactable values are available; use the still-active grant that read the secrets',
    )
  }
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
    const dash = rawArgs.indexOf('--')
    const before = dash === -1 ? rawArgs : rawArgs.slice(0, dash)
    const option = before.find((arg) => arg.startsWith('-'))
    if (option !== undefined) throw new TypeVaultError('invalid', `Unknown scrub option: ${option}`)
    const files = dash === -1 ? before : [...before, ...rawArgs.slice(dash + 1)]
    if (files.length === 0) throw new TypeVaultError('invalid', `usage: typevault scrub <file>... (got ${args.files})`)
    const redactor = await redactorFor()
    for (const file of files) {
      try {
        if (await scrubFile(file, redactor)) print(file)
      } catch (error) {
        if (!(error instanceof TypeVaultError)) throw error
        note(`typevault: ${error.message}`)
        process.exitCode = 1
      }
    }
  },
})

const RequestResponse = z.object({ id: z.string(), url: z.string(), code: z.string(), expiresAt: z.number() })
const RequestDone = z.object({ stored: z.string() })
const REQUEST_POLL_MS = 30_000

type RequestWaitAccess = {
  call<T>(path: string, body: unknown, schema: z.ZodType<T>, timeoutMs?: number): Promise<T>
}

type RequestWait = {
  readonly id: string
  readonly expiresAt: number
}

type RequestWaitOptions = {
  readonly pollMs?: number
  readonly now?: () => number
}

export async function waitForRequest(
  access: RequestWaitAccess,
  request: RequestWait,
  options: RequestWaitOptions = {},
): Promise<z.infer<typeof RequestDone>> {
  const now = options.now ?? Date.now
  const pollMs = options.pollMs ?? REQUEST_POLL_MS
  while (true) {
    const remaining = request.expiresAt - now()
    if (remaining <= 0) throw new TypeVaultError('expired', 'the request expired')
    try {
      return await access.call('/v1/request/wait', { id: request.id }, RequestDone, Math.min(pollMs, remaining))
    } catch (error) {
      if (error instanceof TypeVaultError && error.cause instanceof Error && error.cause.name === 'TimeoutError')
        continue
      throw error
    }
  }
}

export const request = defineCommand({
  meta: { name: 'request', description: 'Ask a human for a secret through a one-time web page (live grants)' },
  args: {
    name: { type: 'positional', description: ENTRY_NAME_SYNTAX, required: true },
    preset: { type: 'string', description: 'Optional field preset' },
    tier: { type: 'string', description: "Tier (defaults to your grant's tier)" },
    reason: { type: 'string', required: true, description: 'Shown to the human' },
  },
  async run({ args }) {
    const resolved = await resolveAccess(process.env)
    if (resolved.kind !== 'live')
      throw new TypeVaultError('unavailable', 'request needs a live grant (the daemon hosts the page)')
    const body = {
      name: args.name,
      preset: args.preset,
      reason: args.reason,
      ...(args.tier === undefined ? {} : { tier: args.tier }),
    }
    const opened = await resolved.access.call('/v1/request', body, RequestResponse)
    print(`Send this link to the human: ${opened.url}\nMatch code: ${opened.code} (post it in the chat too)`)
    const done = await waitForRequest(resolved.access, opened)
    print(`stored as ${done.stored}`)
  },
})

const SOURCES = ['dotenv', 'typeclaw', '1password', 'bitwarden', 'lastpass', 'keepass', 'csv'] as const
const isSource = (value: string): value is ImportSource => SOURCES.some((source) => source === value)
const isVia = (value: string): value is OnePasswordVia => ONEPASSWORD_VIAS.some((via) => via === value)

export const importCommand = defineCommand({
  meta: {
    name: 'import',
    description: 'Import a password-manager export, or 1Password directly, into a tier (one transaction)',
  },
  args: {
    source: { type: 'positional', required: true, description: SOURCES.join(' | ') },
    path: { type: 'positional', required: false, description: 'Export file (omit it to read 1Password directly)' },
    tier: { type: 'string', required: true },
    'password-stdin': { type: 'boolean', description: 'Read the KeePass password from stdin' },
    via: { type: 'string', description: `1Password without a path: ${ONEPASSWORD_VIAS.join(' | ')} (default sdk)` },
    account: { type: 'string', description: '1Password account, repeatable (required with --via sdk)' },
    vault: { type: 'string', description: '1Password vault, repeatable (default: every vault)' },
    tag: { type: 'string', description: 'Only 1Password items with this tag, repeatable' },
  },
  async run({ args, rawArgs }) {
    if (!isSource(args.source)) throw new TypeVaultError('invalid', `source must be one of: ${SOURCES.join(', ')}`)
    const live = args.source === '1password' && args.path === undefined
    if (!live && args.path === undefined) {
      throw new TypeVaultError('invalid', 'usage: typevault import <source> <path> --tier <tier>')
    }
    if (!live && (args.via ?? args.account ?? args.vault ?? args.tag) !== undefined) {
      throw new TypeVaultError('invalid', '--via, --account, --vault and --tag apply only to 1password without a path')
    }
    const via = args.via ?? 'sdk'
    if (!isVia(via)) throw new TypeVaultError('invalid', `--via must be one of: ${ONEPASSWORD_VIAS.join(', ')}`)
    const resolved = await resolveAccess(process.env)
    if (resolved.kind === 'sealed') {
      throw new TypeVaultError('unavailable', 'import needs an unlocked vault or a live grant, not a sealed grant')
    }
    const password = args['password-stdin'] ? await readStdin() : undefined
    const result =
      args.path === undefined
        ? await read1Password({
            via,
            accounts: repeated(rawArgs, '--account'),
            vaults: repeated(rawArgs, '--vault'),
            tags: repeated(rawArgs, '--tag'),
          })
        : await importFrom(args.source, { path: args.path, ...(password === undefined ? {} : { password }) })
    const stored = await resolved.access.importEntries(result.entries, args.tier)
    for (const warning of result.warnings) note(`warning: ${warning}`)
    note(`imported ${stored.length} entries into ${args.tier}`)
  },
})
