import { defineCommand } from 'citty'
import { z } from 'zod'

import { TypeVaultError } from '../../core/errors'
import {
  ENTRY_NAME_SYNTAX,
  ENTRY_REF_SYNTAX,
  findField,
  isFieldName,
  isSecretField,
  parseEntryName,
  parseEntryRef,
  parseEntryType,
  primaryField,
} from '../../core/naming'
import { parseTotpSeed, totpCode, totpRemainingSeconds } from '../../otp/totp'
import { accessOf, resolveAccess } from '../context'
import { csv, note, print, readStdin, repeated, table } from '../output'
import { openBrowser, promptFields } from '../web-prompt'

export const ls = defineCommand({
  meta: { name: 'ls', description: 'List the entries your grant reaches' },
  args: { json: { type: 'boolean', description: 'Print JSON' } },
  async run({ args }) {
    const entries = await (await accessOf(process.env)).list()
    if (args.json) return print(JSON.stringify(entries, null, 2))
    const rows = entries.map((e) => [
      e.name,
      e.type,
      e.tier,
      `r${e.rev}`,
      e.rotated.slice(0, 10),
      e.needsRotation ? 'needs-rotation' : '',
    ])
    print(
      table([
        ['NAME', 'TYPE', 'TIER', 'REV', 'ROTATED', ''],
        ...rows.sort((a, b) => (a[0] ?? '').localeCompare(b[0] ?? '')),
      ]),
    )
  },
})

export const get = defineCommand({
  meta: {
    name: 'get',
    description: 'Print a field. Secret fields need --reveal (they land in your transcript: prefer `typevault run`)',
  },
  args: {
    ref: { type: 'positional', description: ENTRY_REF_SYNTAX, required: true },
    reason: { type: 'string', description: 'Why you need it (audited)' },
    json: { type: 'boolean', description: 'Print every field as JSON (secret fields redacted unless --reveal)' },
    reveal: { type: 'boolean', description: 'Print secret fields in plaintext' },
  },
  async run({ args }) {
    const ref = parseEntryRef(args.ref)
    const value = await (await accessOf(process.env)).get(ref.name, args.reason)
    if (args.json) {
      const fields = Object.fromEntries(
        Object.entries(value.fields).map(([field, secret]) => [
          field,
          args.reveal || !isSecretField(field) ? secret : '<redacted>',
        ]),
      )
      if (!args.reveal) note('secret fields are redacted; pass --reveal to print them')
      return print(JSON.stringify(fields, null, 2))
    }
    const wanted = ref.field ?? primaryField(value.type)
    const field = findField(value.fields, wanted)
    const secret = field === undefined ? undefined : value.fields[field]
    if (field === undefined || secret === undefined) {
      throw new TypeVaultError('not_found', `${value.name} has no field "${wanted}"`)
    }
    if (!args.reveal && isSecretField(field)) {
      throw new TypeVaultError(
        'denied',
        `${value.name}#${field} is secret. Use \`typevault run\` to pass it to a command, ` +
          'or --reveal to print it (it lands in logs and transcripts)',
      )
    }
    print(secret)
  },
})

function parseFields(pairs: readonly string[]): Record<string, string> {
  return Object.fromEntries(
    pairs.map((pair) => {
      const eq = pair.indexOf('=')
      const field = eq === -1 ? '' : pair.slice(0, eq)
      if (!isFieldName(field)) throw new TypeVaultError('invalid', `--field expects name=value, got "${field}"`)
      if (isSecretField(field)) {
        throw new TypeVaultError('invalid', `pass "${field}" on stdin (--stdin or --stdin-json), not as an argument`)
      }
      return [field, pair.slice(eq + 1)]
    }),
  )
}

function parseFieldsJson(text: string): Record<string, string> {
  const fields = z.record(z.string(), z.string()).parse(JSON.parse(text))
  const invalid = Object.keys(fields).find((field) => !isFieldName(field))
  if (invalid !== undefined) throw new TypeVaultError('invalid', `invalid field name "${invalid}"`)
  return fields
}

export const set = defineCommand({
  meta: {
    name: 'set',
    description:
      'Create or update an entry. Pipe the secret on stdin with --stdin, or type it in a browser with --web.',
  },
  args: {
    name: { type: 'positional', description: ENTRY_NAME_SYNTAX, required: true },
    type: { type: 'string', description: 'password | api_key | oauth | ssh | totp | note' },
    tier: {
      type: 'string',
      description: "Tier (defaults to $TYPEVAULT_TIER, else your grant's tier, else the only tier you reach)",
    },
    field: { type: 'string', description: 'k=v, repeatable (non-secret fields; use --stdin for the secret)' },
    stdin: { type: 'boolean', description: 'Read the main secret field from stdin' },
    web: {
      type: 'boolean',
      description: 'Type the fields in a local one-time browser page (default for a new entry from a terminal)',
    },
    env: { type: 'string', description: 'Env var name for the main field in `run`' },
    origin: { type: 'string', description: 'Site this login is for (a hint, never a block)' },
    tag: { type: 'string', description: 'Comma-separated tags' },
    'if-rev': { type: 'string', description: 'Only write if the entry is at this revision' },
    replace: { type: 'boolean', description: 'Replace all fields instead of merging' },
  },
  async run({ args, rawArgs }) {
    const access = await accessOf(process.env)
    const name = parseEntryName(args.name)
    const existing = (await access.list()).find((entry) => entry.name === name)
    const type = args.type === undefined ? existing?.type : parseEntryType(args.type)
    if (type === undefined) throw new TypeVaultError('invalid', 'new entries need --type')
    const given = parseFields(repeated(rawArgs, '--field'))
    const tier = args.tier ?? existing?.tier ?? process.env['TYPEVAULT_TIER']
    const fromStdin = args['stdin-json']
      ? parseFieldsJson(await readStdin())
      : args.stdin
        ? { [primaryField(type)]: await readStdin() }
        : {}
    const web = args.web ?? (existing === undefined && !args.stdin && !args['stdin-json'] && process.stdin.isTTY)
    const fromWeb = web ? await promptFields({ name, type, tier }, showPrompt) : {}
    const fields = { ...given, ...fromStdin, ...fromWeb }
    const base = existing !== undefined && !args.replace ? (await access.get(name, 'merge fields for set')).fields : {}
    const ifRev = args['if-rev'] === undefined ? undefined : z.coerce.number().int().parse(args['if-rev'])
    const tags = csv(args.tag)
    const stored = await access.set({
      name,
      type,
      fields: { ...base, ...fields },
      tier,
      env: args.env,
      origin: args.origin,
      ...(tags.length === 0 ? {} : { tags }),
      ifRev,
    })
    note(`stored ${stored.name} in ${stored.tier} (r${stored.rev})`)
  },
})

function showPrompt(url: string, code: string): void {
  note(`Enter the secret at ${url}\nMatch code: ${code} (the page shows the same code)`)
  if (!openBrowser(url)) note('could not open a browser; open the link yourself')
}

export const rm = defineCommand({
  meta: { name: 'rm', description: 'Remove an entry' },
  args: {
    name: { type: 'positional', description: ENTRY_NAME_SYNTAX, required: true },
    tier: { type: 'string', description: 'Remove the copy in this tier (settles a name held by unrelated tiers)' },
  },
  async run({ args }) {
    await (await accessOf(process.env)).remove(parseEntryName(args.name), args.tier)
    note(`removed ${args.name}. Git history still holds its old ciphertext: rotate the secret if it mattered.`)
  },
})

export const mv = defineCommand({
  meta: { name: 'mv', description: 'Rename an entry' },
  args: {
    from: { type: 'positional', description: ENTRY_NAME_SYNTAX, required: true },
    to: { type: 'positional', description: ENTRY_NAME_SYNTAX, required: true },
  },
  async run({ args }) {
    await (await accessOf(process.env)).move(parseEntryName(args.from), parseEntryName(args.to))
  },
})

export const otp = defineCommand({
  meta: { name: 'otp', description: 'Print the current TOTP code' },
  args: { name: { type: 'positional', description: ENTRY_NAME_SYNTAX, required: true }, reason: { type: 'string' } },
  async run({ args }) {
    const value = await (await accessOf(process.env)).get(parseEntryName(args.name), args.reason)
    const seed = value.type === 'totp' ? value.fields['seed'] : value.fields['totp']
    if (seed === undefined || seed === '') throw new TypeVaultError('not_found', `${value.name} has no TOTP seed`)
    const params = parseTotpSeed(seed)
    const now = new Date()
    print(totpCode(params, now))
    note(`valid for ${totpRemainingSeconds(params, now)}s`)
  },
})

export const whoami = defineCommand({
  meta: { name: 'whoami', description: 'Show how this process reaches the vault' },
  async run() {
    const resolved = await resolveAccess(process.env)
    switch (resolved.kind) {
      case 'live':
        return print(JSON.stringify(await resolved.access.call('/v1/whoami', {}, z.json()), null, 2))
      case 'sealed':
        return print('sealed grant')
      case 'direct':
        return print('direct mode (local keys)')
      default:
        throw new TypeVaultError('invalid', 'unknown access mode')
    }
  },
})
