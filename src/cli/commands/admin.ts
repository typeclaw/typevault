import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { defineCommand } from 'citty'

import { verifyAudit } from '../../audit/log'
import { Admin } from '../../core/admin'
import { adoptCertWrites } from '../../core/adopt'
import { decodeSecretKey } from '../../core/crypto'
import { doctor as runDoctor } from '../../core/doctor'
import { initLocalVault, initVault } from '../../core/init'
import { LOCAL_VAULT_DIR, layoutOf, resolveRoot } from '../../core/layout'
import { Vault } from '../../core/vault'
import { openAdmin, openDirect, wantsGlobal } from '../context'
import { csv, note, print, table } from '../output'

export const init = defineCommand({
  meta: { name: 'init', description: 'Create a vault and its owner key' },
  async run() {
    const env = process.env
    const global = wantsGlobal(env)
    const layout = global ? layoutOf(resolveRoot(env)) : await initLocalVault(join(process.cwd(), LOCAL_VAULT_DIR), env)
    // The new vault's own owner key, never an inherited TYPEVAULT_KEY that belongs to some other vault.
    const ownerKey = global ? await initVault(layout.root) : decodeSecretKey(readFileSync(layout.ownerKey, 'utf8'))
    await new Admin(await Vault.open(layout, [ownerKey], env)).addGroup(STARTER_GROUP)
    print(`vault created at ${global ? layout.root : layout.vault} with group "${STARTER_GROUP}"`)
    const commit = global
      ? 'Only vault/ is safe to commit.'
      : `Commit ${LOCAL_VAULT_DIR}/; its keys stay in ${layout.keys}.`
    note(`owner key: ${layout.ownerKey}\nBack it up offline: it is the only recovery path. ${commit}`)
    note('next: typevault set <name> --type ... --stdin (more groups: typevault group add <name>)')
  },
})

/** Created by `init` so `set` and `grant` work before any group design; as the only group, `set` picks it. */
const STARTER_GROUP = 'default'

const named = { name: { type: 'positional', required: true } } as const
const pair = {
  group: { type: 'positional', required: true },
  included: { type: 'positional', required: true },
} as const

export const group = defineCommand({
  meta: { name: 'group', description: 'Manage groups (owner)' },
  subCommands: {
    ls: defineCommand({
      meta: { name: 'ls' },
      async run() {
        const groups = Object.entries((await openDirect(process.env)).state.groups)
        print(
          table([
            ['GROUP', 'GEN', 'INCLUDES'],
            ...groups.map(([name, g]) => [name, String(g.gen), g.includes.join(', ')]),
          ]),
        )
      },
    }),
    add: defineCommand({
      meta: { name: 'add' },
      args: named,
      run: async ({ args }) => (await openAdmin(process.env)).addGroup(args.name),
    }),
    rm: defineCommand({
      meta: { name: 'rm' },
      args: named,
      run: async ({ args }) => (await openAdmin(process.env)).removeGroup(args.name),
    }),
    include: defineCommand({
      meta: { name: 'include', description: '<group> reaches everything <included> reaches' },
      args: pair,
      run: async ({ args }) => (await openAdmin(process.env)).include(args.group, args.included),
    }),
    exclude: defineCommand({
      meta: { name: 'exclude', description: 'Drop an include and rotate the included group' },
      args: pair,
      async run({ args }) {
        printRotation(args.included, await (await openAdmin(process.env)).exclude(args.group, args.included))
      },
    }),
  },
})

function printRotation(groupName: string, affected: readonly string[]): void {
  print(`rotated ${groupName}`)
  if (affected.length === 0) return
  note('Git history keeps the old ciphertext. Rotate these secrets at their source, then re-set them:')
  for (const name of affected) note(`  ${name}`)
}

export const key = defineCommand({
  meta: { name: 'key', description: 'Export or rotate group keys (owner)' },
  subCommands: {
    export: defineCommand({
      meta: { name: 'export', description: 'Print a group key for a launcher, CI secret or daemon (TYPEVAULT_KEY)' },
      args: named,
      run: async ({ args }) => print(await (await openAdmin(process.env)).exportKey(args.name)),
    }),
    rotate: defineCommand({
      meta: { name: 'rotate', description: 'New key generation; flags every secret the old key reached' },
      args: named,
      run: async ({ args }) => printRotation(args.name, await (await openAdmin(process.env)).rotate(args.name)),
    }),
  },
})

export const ceiling = defineCommand({
  meta: { name: 'ceiling', description: 'The most an admin socket may grant (owner)' },
  subCommands: {
    ls: defineCommand({
      meta: { name: 'ls' },
      async run() {
        const ceilings = Object.entries((await openDirect(process.env)).state.ceilings)
        print(table([['SOCKET', 'GROUP'], ...ceilings]))
      },
    }),
    set: defineCommand({
      meta: { name: 'set' },
      args: { name: { type: 'positional', required: true }, group: { type: 'positional', required: true } },
      run: async ({ args }) => (await openAdmin(process.env)).setCeiling(args.name, args.group),
    }),
    rm: defineCommand({
      meta: { name: 'rm' },
      args: named,
      run: async ({ args }) => (await openAdmin(process.env)).removeCeiling(args.name),
    }),
  },
})

export const signer = defineCommand({
  meta: { name: 'signer', description: 'Extra keys allowed to sign entries (owner)' },
  subCommands: {
    ls: defineCommand({
      meta: { name: 'ls' },
      async run() {
        const signers = Object.entries((await openDirect(process.env)).state.signers)
        print(
          table([['ID', 'GROUPS', 'PUBLIC KEY'], ...signers.map(([id, s]) => [id, s.groups.join(','), s.signPublic])]),
        )
      },
    }),
    add: defineCommand({
      meta: { name: 'add' },
      args: {
        id: { type: 'positional', required: true },
        publicKey: { type: 'positional', required: true, description: 'Base64 Ed25519 public key' },
        groups: { type: 'string', required: true, description: 'Comma-separated groups, or *' },
      },
      run: async ({ args }) => (await openAdmin(process.env)).setSigner(args.id, args.publicKey, csv(args.groups)),
    }),
    rm: defineCommand({
      meta: { name: 'rm' },
      args: named,
      run: async ({ args }) => (await openAdmin(process.env)).removeSigner(args.name),
    }),
  },
})

export const doctor = defineCommand({
  meta: { name: 'doctor', description: 'Verify entries and the audit trail; --fix resolves merges and duplicates' },
  args: {
    fix: { type: 'boolean' },
    'adopt-expired': {
      type: 'boolean',
      description: 'Also keep sealed-grant writes whose certificate expired before adoption',
    },
  },
  async run({ args }) {
    const vault = await openDirect(process.env)
    if (args.fix === true)
      for (const name of await adoptCertWrites(vault, { expired: args['adopt-expired'] === true }))
        print(`adopted sealed write: ${name}`)
    const report = await runDoctor(vault, args.fix === true)
    for (const problem of report.problems) print(`problem: ${problem.file}: ${problem.reason}`)
    for (const file of report.mergesResolved) print(`merged: ${file}`)
    for (const dup of report.duplicatesRemoved) print(`${args.fix === true ? 'removed' : 'duplicate'}: ${dup}`)
    for (const dup of report.duplicatesKept)
      print(
        `same name in several groups: ${dup} (if the groups are unrelated, reads of it fail: keep one with \`typevault rm <name> --group <g>\`)`,
      )
    for (const name of report.needsRotation) print(`needs rotation: ${name}`)
    const audit = verifyAudit(vault.layout)
    print(audit.ok ? `audit: ok (${audit.records} records)` : `audit: BROKEN: ${audit.reason}`)
    if (report.problems.length > 0 || !audit.ok) process.exitCode = 1
  },
})
