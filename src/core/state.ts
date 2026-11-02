import { existsSync, readFileSync } from 'node:fs'

import { z } from 'zod'

import { type PublicKey, type SecretKey, sign, verifySignature } from './crypto'
import { canonicalJson, fromUtf8, type Json, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { atomicWrite } from './fsx'
import type { Layout } from './layout'

export type Group = {
  readonly includes: readonly string[]
  readonly gen: number
  readonly recipient: string
  readonly signPublic: string
}
export type Signer = { readonly signPublic: string; readonly groups: readonly string[] }
export type Groups = Readonly<Record<string, Group>>

/** Everything public about a vault. Groups, signers and ceilings are signed by the operator key. */
export type VaultState = {
  readonly operator: PublicKey
  readonly groups: Groups
  readonly signers: Readonly<Record<string, Signer>>
  readonly ceilings: Readonly<Record<string, string>>
}

const GROUP_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
export function parseGroupName(name: string): string {
  if (!GROUP_NAME.test(name)) throw new TypeVaultError('invalid', `invalid group name "${name}" (use [a-z0-9-])`)
  return name
}

const PublicKeySchema = z.object({ recipient: z.string().startsWith('age1'), signPublic: z.string() })
const GroupSchema = PublicKeySchema.extend({ includes: z.array(z.string()), gen: z.number().int().positive() })
const GroupsBody = z.object({ v: z.literal(1), groups: z.record(z.string(), GroupSchema) })
const SignersBody = z.object({
  v: z.literal(1),
  signers: z.record(z.string(), z.object({ signPublic: z.string(), groups: z.array(z.string()) })),
})
const CeilingsBody = z.object({ v: z.literal(1), ceilings: z.record(z.string(), z.string()) })
const TrustSchema = z.object({ operatorSignPublic: z.string() })

export const signedDoc = (body: Json, key: SecretKey): string =>
  `${JSON.stringify({ body, sig: sign(key.signSecret, utf8(canonicalJson(body))) }, null, 2)}\n`

export const groupsDoc = (groups: Groups, key: SecretKey): string => signedDoc({ v: 1, groups }, key)
export const signersDoc = (signers: VaultState['signers'], key: SecretKey): string => signedDoc({ v: 1, signers }, key)
export const ceilingsDoc = (ceilings: VaultState['ceilings'], key: SecretKey): string =>
  signedDoc({ v: 1, ceilings }, key)

function readSigned<T extends Json>(path: string, schema: z.ZodType<T>, operator: PublicKey): T {
  const doc = z.object({ body: z.json(), sig: z.string() }).parse(JSON.parse(fromUtf8(readFileSync(path))))
  if (!verifySignature(operator.signPublic, utf8(canonicalJson(doc.body)), doc.sig)) {
    throw new TypeVaultError('tampered', `${path} is not signed by the vault operator`)
  }
  return schema.parse(doc.body)
}

/** The operator key is trusted on first use (or pinned via TYPEVAULT_OPERATOR); a changed key is tampering. */
function checkTrust(layout: Layout, operator: PublicKey, env: Readonly<Record<string, string | undefined>>): void {
  const pinned = env['TYPEVAULT_OPERATOR']
  if (pinned !== undefined && pinned !== '') {
    if (pinned !== operator.signPublic)
      throw new TypeVaultError('tampered', 'vault operator does not match TYPEVAULT_OPERATOR')
    return
  }
  if (!existsSync(layout.trustFile)) {
    atomicWrite(layout.trustFile, JSON.stringify({ operatorSignPublic: operator.signPublic }), 0o600)
    return
  }
  const trust = TrustSchema.parse(JSON.parse(fromUtf8(readFileSync(layout.trustFile))))
  if (trust.operatorSignPublic !== operator.signPublic) {
    throw new TypeVaultError('tampered', 'vault operator key changed since this machine first trusted it')
  }
}

export function loadState(layout: Layout, env: Readonly<Record<string, string | undefined>> = process.env): VaultState {
  if (!existsSync(layout.operatorFile))
    throw new TypeVaultError('not_found', `no vault at ${layout.root} (run typevault init)`)
  const operator = PublicKeySchema.parse(JSON.parse(fromUtf8(readFileSync(layout.operatorFile))))
  checkTrust(layout, operator, env)
  return {
    operator,
    groups: readSigned(layout.groupsFile, GroupsBody, operator).groups,
    signers: readSigned(layout.signersFile, SignersBody, operator).signers,
    ceilings: readSigned(layout.ceilingsFile, CeilingsBody, operator).ceilings,
  }
}

/** Every group `name` reaches through includes, itself included. */
export function reach(groups: Groups, name: string): ReadonlySet<string> {
  const seen = new Set<string>()
  const visit = (group: string): void => {
    if (seen.has(group)) return
    seen.add(group)
    for (const included of groups[group]?.includes ?? []) visit(included)
  }
  visit(name)
  return seen
}

export const reachesGroup = (groups: Groups, from: readonly string[], target: string): boolean =>
  from.some((group) => group === '*' || reach(groups, group).has(target))

export const includersOf = (groups: Groups, name: string): readonly string[] =>
  Object.entries(groups)
    .filter(([, group]) => group.includes.includes(name))
    .map(([includer]) => includer)
