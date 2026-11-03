import { watch } from 'node:fs'

import { defineCommand } from 'citty'
import { z } from 'zod'

import { loadLocalKeys } from '../../access/keys'
import { parseTtl } from '../../access/scope'
import { issueSealedGrant } from '../../access/sealed'
import { GrantInfoSchema, IssuedSchema } from '../../admin'
import { readAudit, verifyAudit } from '../../audit/log'
import { TypeVaultError } from '../../core/errors'
import { adminCall, layoutFrom, openDirect } from '../context'
import { csv, print, table } from '../output'

const GrantList = z.array(GrantInfoSchema)

export const grant = defineCommand({
  meta: {
    name: 'grant',
    description: 'Issue a grant (prints the token), or: grant ls | grant revoke <id> | grant revoke --label <label>',
  },
  args: {
    action: { type: 'positional', required: false, description: 'ls | revoke' },
    id: { type: 'positional', required: false },
    tier: { type: 'string', description: 'Comma-separated tiers' },
    only: { type: 'string', description: 'Comma-separated names or globs' },
    ttl: { type: 'string', default: '1h' },
    label: { type: 'string', description: 'Who this is for, e.g. session:abc or ci:deploy' },
    sealed: { type: 'boolean', description: 'Offline bundle: no daemon needed, no revocation' },
  },
  async run({ args }) {
    const env = process.env
    switch (args.action) {
      case 'ls': {
        const grants = await adminCall(env, '/v1/grants', {}, GrantList)
        return print(
          table([
            ['ID', 'LABEL', 'TIERS', 'ONLY', 'EXPIRES'],
            ...grants.map((g) => [g.id, g.label, g.tiers.join(','), g.only.join(','), g.exp]),
          ]),
        )
      }
      case 'revoke': {
        const body = {
          ...(args.id === undefined ? {} : { id: args.id }),
          ...(args.label === undefined ? {} : { label: args.label }),
        }
        const { revoked } = await adminCall(env, '/v1/revoke', body, z.object({ revoked: z.array(z.string()) }))
        return print(`revoked ${revoked.length} grant(s)`)
      }
      case undefined:
      case '':
        break
      default:
        throw new TypeVaultError('invalid', `unknown grant action "${args.action}"`)
    }
    const tiers = csv(args.tier)
    if (tiers.length === 0) throw new TypeVaultError('invalid', 'grant needs --tier')
    const request = { tiers, only: csv(args.only), ttl: args.ttl, label: args.label ?? 'unlabeled' }
    // An issuer holding a key (CI) seals locally; everything else asks the daemon within its ceiling.
    if (args.sealed && loadLocalKeys(layoutFrom(env), env).length > 0) {
      const vault = await openDirect(env)
      return print(await issueSealedGrant(vault, { ...request, ttlMs: parseTtl(args.ttl) }))
    }
    print((await adminCall(env, '/v1/grant', { ...request, sealed: args.sealed === true }, IssuedSchema)).token)
  },
})

export const audit = defineCommand({
  meta: { name: 'audit', description: 'Show the audit trail' },
  args: { label: { type: 'string' }, verify: { type: 'boolean' }, follow: { type: 'boolean' } },
  async run({ args }) {
    const layout = layoutFrom(process.env)
    if (args.verify) {
      const verdict = verifyAudit(layout)
      print(verdict.ok ? `ok (${verdict.records} records)` : `BROKEN: ${verdict.reason}`)
      if (!verdict.ok) process.exitCode = 1
      return
    }
    let shown = 0
    const show = (): void => {
      const records = readAudit(layout)
      for (const record of records.slice(shown))
        if (args.label === undefined || record['label'] === args.label) print(JSON.stringify(record))
      shown = records.length
    }
    show()
    if (args.follow) await new Promise<never>(() => watch(layout.auditLog, show))
  },
})
