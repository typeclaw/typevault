import { existsSync, readFileSync } from 'node:fs'
import { userInfo } from 'node:os'

import { defineCommand } from 'citty'

import { parseTtl } from '../../access/scope'
import { publicKeyOf } from '../../core/crypto'
import { TypeVaultError } from '../../core/errors'
import { atomicWrite } from '../../core/fsx'
import {
  createIdentity,
  decodeMemberPublic,
  encodeMemberPublic,
  type Identity,
  memberPublicOfIdentity,
  openMemberKey,
  readIdentity,
  sealedCopyPath,
  sealMemberKey,
  writeIdentity,
} from '../../core/identity'
import { vaultIdOf } from '../../core/layout'
import { Vault } from '../../core/vault'
import { stopDaemon } from '../../daemon/spawn'
import { export1Password, identityTitle } from '../../export/1password'
import { ONEPASSWORD_VIAS } from '../../import/1password-live'
import {
  DEFAULT_SESSION_MS,
  findLayout,
  layoutFrom,
  openAdmin,
  openPublic,
  unlockSession,
  worktreeSessions,
  type Env,
} from '../context'
import { csv, note, print, table } from '../output'
import { newPassword, passwords } from '../password'

export const identityArgs = {
  name: { type: 'string', description: 'Your member name, the first time (default: your OS user name)' },
  machine: { type: 'boolean', description: 'A machine identity (CI, an agent host): no password, key kept here' },
} as const

type IdentityArgs = {
  readonly name?: string | undefined
  readonly machine?: boolean | undefined
}

/** This device's identity, created on first use. A new human identity prints its Secret Key once. */
export async function ensureIdentity(env: Env, args: IdentityArgs): Promise<Identity> {
  const existing = readIdentity(env)
  if (existing !== undefined) {
    if (args.name !== undefined && args.name !== existing.name) {
      throw new TypeVaultError('conflict', `this device is already "${existing.name}"`)
    }
    return existing
  }
  const kind = args.machine === true ? 'machine' : 'human'
  const name = args.name ?? defaultName()
  const password = kind === 'human' ? await newPassword(passwords()) : undefined
  const { identity } = await createIdentity(name, kind, password)
  writeIdentity(env, identity)
  if (identity.kind === 'human') {
    note(`created identity "${name}". Your Secret Key:\n\n  ${identity.secretKey}\n`)
    note('Save it with your password (a password manager, or on paper): on a new device both are needed to')
    note('get back in (`typevault identity restore`). It stays on this device; never commit it.')
  } else note(`created machine identity "${name}"`)
  return identity
}

const defaultName = (): string =>
  userInfo()
    .username.toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'me'

export const joinCommand = defineCommand({
  meta: { name: 'join', description: 'Ask to join this vault: prints the line an owner runs to add you' },
  args: identityArgs,
  async run({ args }) {
    const env = process.env
    const layout = layoutFrom(env)
    const identity = await ensureIdentity(env, args)
    const vault = await Vault.open(layout, [], env)
    if (vault.state.members[identity.name] !== undefined) return print(`"${identity.name}" is already a member`)
    if (identity.kind === 'human') {
      const copy = sealedCopyPath(layout, identity.name)
      atomicWrite(copy, identity.sealedKey)
      note(`wrote ${copy} (sealed by your password); commit it`)
    }
    note('ask an owner to run:')
    print(
      `typevault member add ${identity.name} ${encodeMemberPublic(memberPublicOfIdentity(identity))} --tier <tiers>`,
    )
  },
})

export const member = defineCommand({
  meta: { name: 'member', description: 'Who can open this vault: people and machines (owner)' },
  subCommands: {
    ls: defineCommand({
      meta: { name: 'ls' },
      async run() {
        const env = process.env
        const { members } = (await openPublic(env)).state
        print(
          table([
            ['MEMBER', 'KIND', 'OWNER', 'TIERS'],
            ...Object.entries(members).map(([name, m]) => [name, m.kind, m.owner ? 'yes' : '', m.tiers.join(', ')]),
          ]),
        )
      },
    }),
    add: defineCommand({
      meta: { name: 'add', description: 'Add a member from the line `typevault join` printed; rotates their tiers' },
      args: {
        name: { type: 'positional', required: true },
        publicKey: { type: 'positional', required: true, description: 'tvp1:... from `typevault join`' },
        tier: { type: 'string', description: 'Comma-separated tiers whose keys they get' },
        owner: { type: 'boolean', description: 'Also an owner: manages tiers, members and grants' },
      },
      async run({ args }) {
        const tiers = csv(args.tier)
        if (tiers.length === 0 && args.owner !== true)
          throw new TypeVaultError('invalid', 'member add needs --tier or --owner')
        const pub = decodeMemberPublic(args.publicKey)
        await (await openAdmin(process.env)).addMember(args.name, { ...pub, owner: args.owner === true, tiers })
        print(`added ${pub.kind} member ${args.name}${tiers.length === 0 ? '' : ` (rotated ${tiers.join(', ')})`}`)
        note('commit the vault so they can pull it')
      },
    }),
    rm: defineCommand({
      meta: { name: 'rm', description: 'Remove a member and rotate every tier they reached' },
      args: { name: { type: 'positional', required: true } },
      async run({ args }) {
        const affected = await (await openAdmin(process.env)).removeMember(args.name)
        print(`removed ${args.name}`)
        if (affected.length === 0) return
        note('They may have kept what they read. Rotate these secrets at their source, then re-set them:')
        for (const name of affected) note(`  ${name}`)
      },
    }),
  },
})

export const identity = defineCommand({
  meta: { name: 'identity', description: "This device's member identity" },
  subCommands: {
    show: defineCommand({
      meta: { name: 'show', description: 'Your name, kind and public key (safe to share)' },
      run() {
        const current = readIdentity(process.env)
        if (current === undefined) throw new TypeVaultError('not_found', 'no identity yet (run typevault init or join)')
        print(
          table([
            ['NAME', current.name],
            ['KIND', current.kind],
            ['PUBLIC KEY', encodeMemberPublic(memberPublicOfIdentity(current))],
          ]),
        )
      },
    }),
    restore: defineCommand({
      meta: { name: 'restore', description: 'Set up a new device from your Secret Key, password and this vault' },
      args: { name: { type: 'positional', required: true } },
      async run({ args }) {
        const env = process.env
        if (readIdentity(env) !== undefined) throw new TypeVaultError('conflict', 'this device already has an identity')
        const layout = layoutFrom(env)
        const copy = sealedCopyPath(layout, args.name)
        if (!existsSync(copy)) throw new TypeVaultError('not_found', `this vault has no sealed key for "${args.name}"`)
        const source = passwords()
        const secretKey = await source.ask('Secret Key: ')
        const sealedKey = readFileSync(copy, 'utf8')
        const key = await openMemberKey(sealedKey, await source.ask('Password: '), secretKey)
        const pub = await publicKeyOf(key)
        const listed = (await Vault.open(layout, [], env)).state.members[args.name]
        if (key.role.kind !== 'member' || key.role.name !== args.name || listed?.recipient !== pub.recipient) {
          throw new TypeVaultError('tampered', `the sealed key does not belong to member "${args.name}"`)
        }
        writeIdentity(env, { v: 1, kind: 'human', name: args.name, secretKey, sealedKey, ...pub })
        print(`restored identity "${args.name}"`)
      },
    }),
    export: defineCommand({
      meta: { name: 'export', description: 'Store your Secret Key (or a machine key) in 1Password' },
      args: {
        to: { type: 'string', required: true, description: '1password' },
        via: { type: 'string', description: `${ONEPASSWORD_VIAS.join(' | ')} (default: op when installed, else sdk)` },
        account: { type: 'string', description: '1Password account (required with sdk or several op accounts)' },
        vault: { type: 'string', required: true, description: '1Password vault' },
        title: { type: 'string', description: 'Item title (default: TypeVault identity <name>)' },
        replace: { type: 'boolean', description: 'Archive an existing item with the same title' },
      },
      async run({ args }) {
        if (args.to !== '1password') throw new TypeVaultError('invalid', '--to must be 1password')
        const via = ONEPASSWORD_VIAS.find((candidate) => candidate === args.via)
        if (args.via !== undefined && via === undefined) {
          throw new TypeVaultError('invalid', `--via must be one of: ${ONEPASSWORD_VIAS.join(', ')}`)
        }
        const current = readIdentity(process.env)
        if (current === undefined) throw new TypeVaultError('not_found', 'no identity yet (run typevault init or join)')
        const item = {
          title: args.title ?? identityTitle(current.name),
          credential: current.kind === 'human' ? current.secretKey : current.key,
          details: {
            name: current.name,
            kind: current.kind,
            'public key': encodeMemberPublic(memberPublicOfIdentity(current)),
          },
        }
        const used = await export1Password(item, {
          ...(via === undefined ? {} : { via }),
          ...(args.account === undefined ? {} : { account: args.account }),
          vault: args.vault,
          replace: args.replace === true,
        })
        print(`stored "${item.title}" in 1Password vault "${args.vault}" (via ${used})`)
        if (current.kind === 'machine') note(`use it: TYPEVAULT_KEY="op://${args.vault}/${item.title}/credential"`)
      },
    }),
  },
})

const MAX_TIMER_MS = 2 ** 31 - 1

export const unlock = defineCommand({
  meta: { name: 'unlock', description: 'Unlock this vault for a while, so you and your agents can use it' },
  args: { for: { type: 'string', default: '8h', description: 'How long, e.g. 30m, 8h' } },
  async run({ args }) {
    const env = process.env
    const ttlMs = args.for === undefined ? DEFAULT_SESSION_MS : parseTtl(args.for)
    if (ttlMs > MAX_TIMER_MS) throw new TypeVaultError('invalid', '--for is too long (at most 24 days)')
    const started = await unlockSession(env, passwords(), ttlMs)
    const id = vaultIdOf((await openPublic(env)).state.owner.signPublic)
    print(started ? `unlocked vault ${id} for ${args.for}` : `vault ${id} is already unlocked`)
  },
})

export const lock = defineCommand({
  meta: { name: 'lock', description: 'Lock this vault now: stops the daemon and ends every session' },
  async run() {
    const layout = findLayout(process.env)
    if (layout === undefined) throw new TypeVaultError('not_found', 'no vault here')
    // A session unlocked in another worktree would only be shared here again on the next read.
    const worktrees = await worktreeSessions(layout, process.env)
    let locked = false
    for (const target of [...worktrees, layout]) {
      locked =
        (await stopDaemon(target).then(
          () => true,
          (error: unknown) => {
            if (error instanceof TypeVaultError && error.code === 'not_found') return false
            throw error
          },
        )) || locked
    }
    print(locked ? 'locked' : 'already locked')
  },
})

export const passwd = defineCommand({
  meta: { name: 'passwd', description: 'Change your password (your key and every vault stay the same)' },
  async run() {
    const env = process.env
    const current = readIdentity(env)
    if (current?.kind !== 'human') throw new TypeVaultError('invalid', 'only a human identity has a password')
    const source = passwords()
    const key = await openMemberKey(current.sealedKey, await source.ask('Current password: '), current.secretKey)
    const sealedKey = await sealMemberKey(key, await newPassword(source), current.secretKey)
    writeIdentity(env, { ...current, sealedKey })
    print('password changed')
    const layout = findLayout(env)
    const copy = layout === undefined ? undefined : sealedCopyPath(layout, current.name)
    if (copy !== undefined && existsSync(copy)) {
      atomicWrite(copy, sealedKey)
      note(`updated ${copy}; commit it. Other vaults pick up the change on your next unlock there.`)
    }
  },
})
