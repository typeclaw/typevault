import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { defineCommand } from 'citty'
import { z } from 'zod'

import { TypeVaultError } from '../../core/errors'
import { isDaemonAlive } from '../../daemon/client'
import { startDaemon } from '../../daemon/daemon'
import { ensureDaemon } from '../../daemon/spawn'
import { adminCall, layoutFrom } from '../context'
import { note, print } from '../output'

const port = (value: string | undefined): number | undefined =>
  value === undefined || value === '' ? undefined : z.coerce.number().int().parse(value)

export const daemon = defineCommand({
  meta: { name: 'daemon', description: 'The background issuer (usually started automatically)' },
  subCommands: {
    run: defineCommand({
      meta: { name: 'run', description: 'Run in the foreground' },
      async run() {
        const env = process.env
        const promptPort = port(env['TYPEVAULT_PROMPT_PORT'])
        const publicUrl = env['TYPEVAULT_PUBLIC_URL']
        const running = await startDaemon({
          layout: layoutFrom(env),
          env,
          prompt: {
            ...(promptPort === undefined ? {} : { port: promptPort }),
            ...(publicUrl === undefined ? {} : { publicUrl }),
          },
        })
        note(`typevault daemon ready (admin sockets: ${running.ceilings.map((c) => c.name).join(', ')})`)
        const { promise, resolve } = Promise.withResolvers<void>()
        process.once('SIGINT', resolve)
        process.once('SIGTERM', resolve)
        await promise
        await running.stop()
      },
    }),
    start: defineCommand({
      meta: { name: 'start' },
      run: async () => ensureDaemon(layoutFrom(process.env), process.env),
    }),
    stop: defineCommand({
      meta: { name: 'stop' },
      async run() {
        const pidFile = join(layoutFrom(process.env).run, 'daemon.pid')
        if (!existsSync(pidFile)) throw new TypeVaultError('not_found', 'no daemon is running')
        process.kill(z.coerce.number().int().parse(readFileSync(pidFile, 'utf8')), 'SIGTERM')
      },
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
