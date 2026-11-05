import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { EventEmitter, once } from 'node:events'
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { TypeVaultError } from '../../core/errors'
import { waitForRequest } from './run'

const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

const CLI = join(import.meta.dir, '..', 'index.ts')
const SECRET = 'dummy-value-0001'
const PADDING = '.'.repeat(256)
let base: string
let project: string
let env: Record<string, string>

async function cli(args: readonly string[], stdin = '') {
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
  expect({ code, stderr: code === 0 ? '' : stderr }).toEqual({ code: 0, stderr: '' })
  return stdout.trim()
}

beforeEach(async () => {
  base = realpathSync(mkdtempSync(join(SHORT_TMP, 'tv-run-')))
  project = join(base, 'project')
  mkdirSync(project)
  env = { PATH: process.env['PATH'] ?? '', HOME: base, XDG_CONFIG_HOME: join(base, 'config') }
  await cli(['init', '--machine'])
  await cli(['set', 'svc', '--preset', 'api_key', '--stdin'], SECRET)
})

afterEach(() => rmSync(base, { recursive: true, force: true }))

function killIfRunning(pid: number): void {
  try {
    process.kill(pid, 'SIGKILL')
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ESRCH')) throw error
  }
}

async function signalRun(signal: NodeJS.Signals, terminal = false): Promise<void> {
  const descendant = `
    process.on(${JSON.stringify(signal)}, () => {
      console.log('DESCENDANT(${signal})', process.env.SVC);
      process.exit(0);
    });
    setInterval(() => {}, 1000);
    console.log('ready');
  `
  const script = `
    const child = Bun.spawn([process.execPath, '-e', ${JSON.stringify(descendant)}], {
      env: process.env, stdin: 'ignore', stdout: 'pipe', stderr: 'inherit',
    });
    console.log('SPAWNED(' + process.pid + ',' + child.pid + ')${PADDING}');
    const reader = child.stdout.getReader();
    await reader.read();
    reader.releaseLock();
    const output = (async () => {
      let text = '';
      for await (const chunk of child.stdout) text += new TextDecoder().decode(chunk);
      return text;
    })();
    let received = false;
    process.on(${JSON.stringify(signal)}, () => {
      if (received) process.exit(99);
      received = true;
      console.log('RECEIVED(${signal})${PADDING}');
    });
    process.stdin.once('data', async () => {
      await child.exited;
      console.log(await output);
      console.log('stdout', process.env.SVC);
      console.error('stderr', process.env.SVC);
      process.exit(42);
    });
    process.stdin.resume();
    console.log('READY(' + process.pid + ',' + child.pid + ')${PADDING}');
  `
  const events = new EventEmitter()
  let output = ''
  const decoder = new TextDecoder()
  const onOutput = (chunk: Uint8Array): void => {
    output += decoder.decode(chunk, { stream: true })
    events.emit('output')
  }
  const args = [process.execPath, CLI, 'run', '--only', 'svc', '--', process.execPath, '-e', script]
  const proc = terminal
    ? Bun.spawn(args, {
        cwd: project,
        env,
        terminal: { cols: 300, rows: 40, data: (_tty, data) => onOutput(data) },
      })
    : Bun.spawn(args, { cwd: project, env, stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' })
  const drains = [proc.stdout, proc.stderr]
    .filter((stream) => stream instanceof ReadableStream)
    .map(async (stream) => {
      for await (const chunk of stream) onOutput(chunk)
    })
  const until = async (pattern: RegExp): Promise<void> => {
    const deadline = AbortSignal.timeout(5000)
    try {
      while (!pattern.test(output)) await once(events, 'output', { signal: deadline })
    } catch (error) {
      throw new Error(`Waiting for ${pattern}, received: ${output}`, { cause: error })
    }
  }
  let pids: number[] = []
  try {
    // Ready is emitted only after both processes install their signal handlers.
    // Padding makes it visible even while the redactor retains a possible secret suffix.
    await until(/READY\((\d+),(\d+)\)/)
    const ready = /READY\((\d+),(\d+)\)/.exec(output)
    pids = [Number(ready?.[1]), Number(ready?.[2])]

    if (terminal) proc.terminal?.write('\x03')
    else proc.kill(signal)
    await until(new RegExp(`RECEIVED\\(${signal}\\)`))
    // The child deliberately waits for input after receiving the signal.
    expect(proc.exitCode).toBeNull()
    if (terminal) proc.terminal?.write('finish\n')
    else if (typeof proc.stdin !== 'number') proc.stdin?.write('finish\n')
    const code = await Promise.race([
      proc.exited,
      new Promise<never>((_, reject) => {
        const deadline = AbortSignal.timeout(5000)
        deadline.addEventListener('abort', () => reject(deadline.reason), { once: true })
      }),
    ])
    await Promise.all(drains)

    expect(code).toBe(42)
    expect(output).toContain(`DESCENDANT(${signal})`)
    expect(output.match(/\[redacted\]/g)).toHaveLength(3)
    expect(output).not.toContain(SECRET)
    for (const pid of pids) expect(() => process.kill(pid, 0)).toThrow(expect.objectContaining({ code: 'ESRCH' }))
  } finally {
    const spawned = /SPAWNED\((\d+),(\d+)\)/.exec(output)
    if (spawned !== null) pids = [Number(spawned[1]), Number(spawned[2])]
    for (const pid of pids) killIfRunning(pid)
    if (proc.exitCode === null) proc.kill('SIGKILL')
    await proc.exited
    proc.terminal?.close()
    await Promise.all(drains)
  }
}

// Windows has no POSIX process groups or catchable TERM/INT/HUP signals.
describe.skipIf(process.platform === 'win32')('POSIX run shutdown', () => {
  it.each(['SIGTERM', 'SIGINT', 'SIGHUP'] as const)(
    'forwards %s to the child group, redacts shutdown output, and waits for exit without orphans (#60)',
    async (signal) => signalRun(signal),
    20_000,
  )

  it(
    'delivers terminal Ctrl-C once and waits for the child group to exit (#60)',
    async () => signalRun('SIGINT', true),
    20_000,
  )
})

const timeout = (): TypeVaultError =>
  new TypeVaultError('unavailable', 'the typevault daemon request timed out', {
    cause: new DOMException('The operation timed out.', 'TimeoutError'),
  })

it('keeps polling after transport timeouts until the request settles', async () => {
  let calls = 0
  let now = 0
  const access = {
    async call<T>(_path: string, _body: unknown, schema: { parse(value: unknown): T }): Promise<T> {
      calls += 1
      now += 30
      if (calls < 3) throw timeout()
      return schema.parse({ stored: 'resend' })
    },
  }

  await expect(
    waitForRequest(access, { id: 'request-id', expiresAt: 100 }, { pollMs: 30, now: () => now }),
  ).resolves.toEqual({ stored: 'resend' })
})

it('stops polling with an expired error at the request deadline', async () => {
  let now = 0
  const access = {
    async call<T>(): Promise<T> {
      now += 30
      throw timeout()
    },
  }

  await expect(
    waitForRequest(access, { id: 'request-id', expiresAt: 50 }, { pollMs: 30, now: () => now }),
  ).rejects.toMatchObject({ code: 'expired' })
})
