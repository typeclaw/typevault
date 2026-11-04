import { defineCommand } from 'citty'
import { z } from 'zod'

import { machineKeys } from '../../access/keys'
import { parseTtl } from '../../access/scope'
import { decodeSecretKey } from '../../core/crypto'
import { localLayout } from '../../core/layout'
import { isDaemonAlive } from '../../daemon/client'
import { startDaemon } from '../../daemon/daemon'
import { ensureDaemon, stopDaemon } from '../../daemon/spawn'
import { adminCall, DEFAULT_SESSION_MS, layoutFrom } from '../context'
import { note, print, readStdin } from '../output'

const port = (value: string | undefined): number | undefined =>
  value === undefined || value === '' ? undefined : z.coerce.number().int().parse(value)

export const daemon = defineCommand({
  meta: { name: 'daemon', description: 'The background issuer (usually started automatically)' },
  subCommands: {
    run: defineCommand({
      meta: { name: 'run', description: 'Run in the foreground' },
      args: {
        'key-stdin': { type: 'boolean', description: 'Read an unlocked member key from stdin (used by unlock)' },
        ttl: { type: 'string', description: 'Stop after this long, e.g. 8h (used by unlock)' },
        vault: {
          type: 'string',
          description: 'The project vault to serve, instead of the one found here (used by unlock)',
        },
        'source-lock': {
          type: 'string',
          description: 'Serve only while the daemon holding this lock runs (used to share a session with a worktree)',
        },
      },
      async run({ args }) {
        const env = process.env
        const promptPort = port(env['TYPEVAULT_PROMPT_PORT'])
        const publicUrl = env['TYPEVAULT_PUBLIC_URL']
        const fromStdin = args['key-stdin'] === true
        const ttlMs = args.ttl === undefined ? undefined : parseTtl(args.ttl)
        const sourceLock = args['source-lock']
        const running = await startDaemon({
          layout: args.vault === undefined ? layoutFrom(env) : localLayout(args.vault, env),
          env,
          keys: fromStdin ? [decodeSecretKey(await readStdin())] : machineKeys(env),
          prompt: {
            ...(promptPort === undefined ? {} : { port: promptPort }),
            ...(publicUrl === undefined ? {} : { publicUrl }),
          },
          ...(fromStdin
            ? { session: { ttlMs: ttlMs ?? DEFAULT_SESSION_MS, ...(sourceLock === undefined ? {} : { sourceLock }) } }
            : {}),
        })
        note(`typevault daemon ready (admin sockets: ${running.ceilings.map((c) => c.name).join(', ') || 'none'})`)
        const { promise, resolve } = Promise.withResolvers<void>()
        process.once('SIGINT', resolve)
        process.once('SIGTERM', resolve)
        void running.stopRequested.then(resolve)
        const expiry = ttlMs === undefined ? undefined : setTimeout(resolve, ttlMs)
        await promise
        clearTimeout(expiry)
        await running.stop()
      },
    }),
    start: defineCommand({
      meta: { name: 'start' },
      run: async () => ensureDaemon(layoutFrom(process.env), process.env),
    }),
    stop: defineCommand({
      meta: { name: 'stop' },
      run: async () => stopDaemon(layoutFrom(process.env)),
    }),
    status: defineCommand({
      meta: { name: 'status' },
      async run() {
        const layout = layoutFrom(process.env)
        if (!(await isDaemonAlive(layout.agentSocket))) return print('not running')
        print(JSON.stringify(await adminCall(process.env, '/v1/status', {}, z.json()), null, 2))
      },
    }),
  },
})
