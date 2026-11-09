import { afterEach, beforeEach, expect } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import type { Subprocess } from 'bun'

import { type Layout } from '../../core/layout'

export const envIn = (dir: string) => ({ TYPEVAULT_DIR: join(dir, 'vault'), XDG_CONFIG_HOME: dir })

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
export const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

export const CLI = join(import.meta.dir, '..', 'index.ts')
export const PASSWORD = 'correct horse battery staple'

export type Run = { readonly code: number; readonly stdout: string; readonly stderr: string }

export let base: string
export let project: string
export let owner: Record<string, string>
export let standIn: Subprocess | undefined

export async function cli(args: readonly string[], env: Record<string, string>, stdin = ''): Promise<Run> {
  const proc = Bun.spawn([process.execPath, CLI, ...args], {
    cwd: project,
    env,
    stdin: new TextEncoder().encode(stdin),
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const [code, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])
  return { code, stdout, stderr }
}

export const succeeds = (run: Run): Run => {
  expect({ code: run.code, stderr: run.code === 0 ? '' : run.stderr }).toEqual({ code: 0, stderr: '' })
  return run
}

beforeEach(async () => {
  base = realpathSync(mkdtempSync(join(SHORT_TMP, 'tvc-')))
  project = join(base, 'p')
  mkdirSync(project)
  owner = { PATH: process.env['PATH'] ?? '', XDG_CONFIG_HOME: join(base, 'alice') }
  const init = succeeds(await cli(['init', '--name', 'alice', '--vault-password-stdin'], owner, `${PASSWORD}\n`))
  expect(init.stderr).toContain('TVSK-')
})

afterEach(async () => {
  await cli(['lock'], owner)
  standIn?.kill('SIGKILL')
  standIn = undefined
  rmSync(base, { recursive: true, force: true })
})

// Stands in for a daemon from another release: like a real one it holds the daemon lock and answers pings with its
// PID, but with another version. Told to stop (SIGTERM, or over its control socket on Windows), it exits.
export const OTHER_RELEASE_DAEMON = `
import { holdLock } from ${JSON.stringify(join(import.meta.dir, '..', '..', 'core', 'lock.ts'))}
const [lock, agent, control] = process.argv.slice(2)
if (holdLock(lock) === undefined) process.exit(2)
export const stop = () => {
  server.stop(true)
  shutdown.stop(true)
  process.exit(0)
}
export const server = Bun.serve({ unix: agent, fetch: () => Response.json({ ok: true, pid: process.pid, version: '0.0.0-other' }) })
export const shutdown = Bun.serve({
  unix: control,
  fetch: () => {
    setTimeout(stop, 0)
    return Response.json({ ok: true })
  },
})
process.once('SIGTERM', stop)
console.log('ready')
`

export async function otherReleaseDaemon(layout: Layout): Promise<Subprocess> {
  const script = join(base, 'other-release.ts')
  writeFileSync(script, OTHER_RELEASE_DAEMON)
  mkdirSync(layout.run, { recursive: true, mode: 0o700 })
  mkdirSync(layout.sockets, { recursive: true, mode: 0o700 })
  const daemon = Bun.spawn([process.execPath, script, layout.daemonLock, layout.agentSocket, layout.controlSocket], {
    stdout: 'pipe',
  })
  standIn = daemon
  const { value } = await daemon.stdout.getReader().read()
  expect(new TextDecoder().decode(value)).toContain('ready')
  return daemon
}
