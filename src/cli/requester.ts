import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { basename, dirname } from 'node:path'

import { type ArgsDef, type CommandDef, parseArgs } from 'citty'

import type { Layout } from '../core/layout'
import { table } from './output'

/**
 * Who asks for a password or a touch, and why: which program ran this command (the agent session, when an agent did),
 * which vault, the command, the working directory, and the `--reason` it gave. With several agents running, this
 * tells them apart. Everything but `purpose` comes from outside (argv, the process table, the filesystem), so the
 * prompts render each field as one line of printable text.
 */
export type UnlockRequest = {
  readonly purpose: string
  readonly program?: string
  readonly vault: string
  readonly where: string
  readonly command: string
  readonly reason?: string
}

export async function unlockRequest(purpose: string, layout: Layout | undefined): Promise<UnlockRequest> {
  const program = await parentProgram().catch(() => undefined)
  const cwd = process.cwd()
  const home = homedir()
  const where = cwd === home || cwd.startsWith(`${home}/`) ? `~${cwd.slice(home.length)}` : cwd
  const reason = command.reason
  return {
    purpose,
    ...(program === undefined ? {} : { program }),
    vault:
      layout?.scope === 'global' ? 'the global vault' : basename(layout === undefined ? cwd : dirname(layout.vault)),
    where,
    command: commandOf(command.args),
    ...(reason === undefined ? {} : { reason }),
  }
}

/**
 * "typevault is trying to <this>." The caller's reason completes the sentence; the dialog wraps at about 30
 * characters, so it names only what a person decides on. The "for <program> in <vault>" tail is always ours, so a
 * misleading reason still shows who gave it. The command and working directory are in the terminal.
 */
export function touchIdReason(request: UnlockRequest): string {
  const program = request.program === undefined ? '' : ` for ${shown(request.program)}`
  return `${wanted(request)}${program} in ${shown(request.vault)}`
}

/** The lines above a password prompt. */
export function promptHeader(request: UnlockRequest): string {
  const rows = [
    ['  vault', shown(request.vault)],
    ['  command', shown(request.command)],
    ['  in', shown(request.where)],
  ]
  const program = request.program === undefined ? 'A command' : shown(request.program)
  return `${program} wants to ${wanted(request)}\n${table(rows)}`
}

/**
 * The nearest ancestor that is a program of its own: shells and launchers in between are skipped, and a script run
 * by an interpreter is named by its script. `ps` lists `pid ppid args`, one process per line.
 */
export function programIn(ps: string, parent: number): string | undefined {
  const processes = new Map<number, { readonly ppid: number; readonly args: readonly string[] }>()
  for (const line of ps.split('\n')) {
    const [pid, ppid, ...args] = line.trim().split(/\s+/)
    if (pid !== undefined && ppid !== undefined && args.length > 0)
      processes.set(Number(pid), { ppid: Number(ppid), args })
  }
  let pid = parent
  for (let depth = 0; depth < 32 && pid > 1; depth += 1) {
    const found = processes.get(pid)
    if (found === undefined) return undefined
    const name = programName(found.args)
    if (name !== undefined && !PASS_THROUGH.has(name)) return name
    pid = found.ppid
  }
  return undefined
}

const SHELLS = ['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh', 'tcsh', 'csh', 'nu']
const LAUNCHERS = [
  'env',
  'login',
  'sudo',
  'nohup',
  'timeout',
  'xargs',
  'npm',
  'npx',
  'pnpm',
  'yarn',
  'bunx',
  'typevault',
]
const PASS_THROUGH = new Set([...SHELLS, ...LAUNCHERS])
const INTERPRETERS = new Set(['node', 'bun', 'deno', 'python', 'python3', 'ruby'])
export const UNLOCK = 'unlock your vault'
const SHOWN_LENGTH = 80
const REASON = '--reason'

// Never `ps` from PATH: this runs before authentication, and a project can put its own `ps` first on PATH.
const PS = ['/bin/ps', '/usr/bin/ps'].find((path) => existsSync(path))

async function parentProgram(): Promise<string | undefined> {
  if (PS === undefined) return undefined
  const ps = Bun.spawn([PS, '-A', '-o', 'pid=,ppid=,args='], { stdout: 'pipe', stderr: 'ignore' })
  const [out, code] = await Promise.all([new Response(ps.stdout).text(), ps.exited])
  return code === 0 ? programIn(out, process.ppid) : undefined
}

/**
 * A script run by an interpreter is named by its file only in the plain script form: the script path right after the
 * interpreter. Any option first (inline code like `node -e ...` or `python -cCODE`, an option whose value could be
 * anything, `ps` splitting a quoted argument) means the interpreter's name, so no source or option value shows.
 */
function programName(args: readonly string[]): string | undefined {
  const [first, script] = args
  if (first === undefined) return undefined
  // A login shell is listed as `-zsh`.
  const name = basename(first).replace(/^-/, '')
  if (!INTERPRETERS.has(name)) return name
  if (script === undefined || script.startsWith('-') || !(script.includes('/') || SCRIPT_FILE.test(script))) {
    return name
  }
  return basename(script).replace(SCRIPT_FILE, '')
}

const SCRIPT_FILE = /\.[cm]?[jt]sx?$|\.py$|\.rb$/

/**
 * The command citty dispatches to: the words naming it (`set`, `tier add`), the arguments citty was given (global
 * flags already taken out), and its `--reason` as citty parses it for that command, the value it audits. A command
 * that declares no `--reason` has none: the prompts never re-parse argv, so they can't read a field or an entry name
 * as a reason.
 */
export type Dispatched = {
  readonly words: readonly string[]
  readonly args: readonly string[]
  readonly reason?: string
}

let command: Dispatched = { words: [], args: [] }

/** Set by the CLI entry point to the command citty dispatches to. */
export function commandIs(dispatched: Dispatched): void {
  command = dispatched
}

type CommandLevel = Pick<CommandDef, 'args' | 'subCommands'>

/**
 * The command citty dispatches to (`tier add`), found the way citty finds it: at each level, the first argument that
 * isn't an option or an option's value, up to `--`. Never an argument.
 */
export function commandPath(root: CommandLevel, rawArgs: readonly string[]): Dispatched {
  const words: string[] = []
  let level = root
  let args = rawArgs
  for (;;) {
    const subCommands = level.subCommands
    const listed = typeof subCommands === 'object' && !(subCommands instanceof Promise)
    const index = listed ? subCommandIndex(args, level.args) : -1
    const name = args[index]
    const next = listed && name !== undefined ? subCommands[name] : undefined
    if (name === undefined || typeof next !== 'object' || next instanceof Promise) {
      const reason = reasonOf(args, argsOf(level.args))
      return { words, args: rawArgs, ...(reason === undefined ? {} : { reason }) }
    }
    words.push(name)
    level = next
    args = args.slice(index + 1)
  }
}

function reasonOf(args: readonly string[], defs: ArgsDef): string | undefined {
  if (!takesValue(REASON, defs)) return undefined
  try {
    const reason: unknown = parseArgs([...args], defs)['reason']
    return typeof reason === 'string' && reason !== '' ? reason : undefined
  } catch (error) {
    // citty rejects these arguments the same way before the command runs, so no prompt shows to need a reason.
    if (error instanceof Error && error.name === 'CLIError') return undefined
    throw error
  }
}

const argsOf = (argsDef: CommandLevel['args']): ArgsDef =>
  typeof argsDef === 'object' && !(argsDef instanceof Promise) ? argsDef : {}

function subCommandIndex(args: readonly string[], argsDef: CommandLevel['args']): number {
  const defs = argsOf(argsDef)
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? ''
    if (arg === '--') return -1
    if (!arg.startsWith('-')) return index
    if (!arg.includes('=') && takesValue(arg, defs)) index += 1
  }
  return -1
}

function takesValue(flag: string, defs: ArgsDef): boolean {
  const name = flag.replace(/^-{1,2}/, '')
  return Object.entries(defs).some(
    ([key, def]) =>
      (def.type === 'string' || def.type === 'enum') &&
      (camel(key) === camel(name) || [def.alias ?? []].flat().includes(name)),
  )
}

const camel = (text: string): string => text.replaceAll(/-([a-z])/g, (_, letter: string) => letter.toUpperCase())

/**
 * The command and, for `run`, the child's program name: never an argument's value, since an entry name, a
 * `--field password=...` or a child's arguments can hold a secret, and the prompt may show before they are rejected.
 */
function commandOf(argv: readonly string[]): string {
  const child = command.words[0] === 'run' && argv.includes('--') ? argv[argv.indexOf('--') + 1] : undefined
  return ['typevault', ...command.words, ...(child === undefined ? [] : ['--', basename(child)])].join(' ')
}

/**
 * The caller's reason stands in for a plain unlock. Any other purpose (an owner change, which the same touch approves)
 * is always said, the reason after it, so a reason can't hide what the touch allows.
 */
function wanted(request: UnlockRequest): string {
  const reason = request.reason === undefined ? '' : shown(request.reason)
  if (reason === '') return request.purpose
  return request.purpose === UNLOCK ? reason : `${request.purpose} to ${reason}`
}

/** One line of printable text: control, format and line-separator characters could redraw or fake the prompt. */
function shown(text: string): string {
  const line = text.replaceAll(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, ' ').trim()
  return line.length > SHOWN_LENGTH ? `${line.slice(0, SHOWN_LENGTH - 1)}…` : line
}
