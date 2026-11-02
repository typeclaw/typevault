import { defineCommand } from 'citty'

import { verifyAudit } from '../../audit/log'
import { doctor as runDoctor } from '../../core/doctor'
import { initVault } from '../../core/init'
import { layoutFrom, openAdmin, openDirect } from '../context'
import { csv, note, print, table } from '../output'

export const init = defineCommand({
  meta: { name: 'init', description: 'Create a vault and its operator key' },
  async run() {
    const layout = layoutFrom(process.env)
    await initVault(layout.root)
    print(`vault created at ${layout.root}`)
    note(
      `operator key: ${layout.operatorKey}\nBack it up offline: it is the only recovery path. Only vault/ is safe to commit.`,
    )
    note('next: typevault group add <name>, then typevault set <name> --type ... --group <name> --stdin')
  },
})

const named = { name: { type: 'positional', required: true } } as const
const pair = {
  group: { type: 'positional', required: true },
  included: { type: 'positional', required: true },
} as const

export const group = defineCommand({
  meta: { name: 'group', description: 'Manage groups (operator)' },
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
  meta: { name: 'key', description: 'Export or rotate group keys (operator)' },
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
  meta: { name: 'ceiling', description: 'The most an admin socket may grant (operator)' },
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
  meta: { name: 'signer', description: 'Extra keys allowed to sign entries (operator)' },
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
  args: { fix: { type: 'boolean' } },
  async run({ args }) {
    const vault = await openDirect(process.env)
    const report = await runDoctor(vault, args.fix === true)
    for (const problem of report.problems) print(`problem: ${problem.file}: ${problem.reason}`)
    for (const file of report.mergesResolved) print(`merged: ${file}`)
    for (const dup of report.duplicatesRemoved) print(`${args.fix === true ? 'removed' : 'duplicate'}: ${dup}`)
    for (const name of report.needsRotation) print(`needs rotation: ${name}`)
    const audit = verifyAudit(vault.layout)
    print(audit.ok ? `audit: ok (${audit.records} records)` : `audit: BROKEN: ${audit.reason}`)
    if (report.problems.length > 0 || !audit.ok) process.exitCode = 1
  },
})
