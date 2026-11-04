import { existsSync, realpathSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'

/** git's own variables (set inside hooks, say) would point it at another repository than the vault's. */
const gitEnv = (): Record<string, string | undefined> =>
  Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('GIT_')))

async function git(cwd: string, args: readonly string[]): Promise<string | undefined> {
  let proc: Bun.Subprocess<'ignore', 'pipe', 'ignore'>
  try {
    proc = Bun.spawn(['git', ...args], { cwd, env: gitEnv(), stdin: 'ignore', stdout: 'pipe', stderr: 'ignore' })
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return undefined
    throw error
  }
  const [code, output] = await Promise.all([proc.exited, new Response(proc.stdout).text()])
  return code === 0 ? output : undefined
}

/**
 * The same vault in every other worktree of the git repository `vault` is checked out in: the checkouts an unlocked
 * session is shared between. Only worktrees the repository itself lists count, so a directory that merely copies the
 * vault or clones the repository is never one.
 */
export async function worktreeVaults(vault: string): Promise<readonly string[]> {
  if (!existsSync(vault)) return []
  const own = realpathSync(vault)
  const top = (await git(dirname(own), ['rev-parse', '--show-toplevel']))?.trim()
  if (top === undefined || top === '') return []
  const path = relative(realpathSync(top), own)
  const listed = (await git(dirname(own), ['worktree', 'list', '--porcelain'])) ?? ''
  return listed
    .split('\n')
    .filter((line) => line.startsWith('worktree '))
    .map((line) => join(line.slice('worktree '.length), path))
    .filter((candidate) => existsSync(join(candidate, 'owner.json')))
    .map((candidate) => realpathSync(candidate))
    .filter((candidate) => candidate !== own)
}
