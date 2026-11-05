import { existsSync, realpathSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'

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
  const checkouts = listed
    .split('\n')
    .filter((line) => line.startsWith('worktree '))
    .map((line) => line.slice('worktree '.length))
  if (!checkouts.some((checkout) => existsSync(checkout) && realpathSync(checkout) === realpathSync(top))) return []
  const common = (await git(dirname(own), ['rev-parse', '--git-common-dir']))?.trim()
  if (common === undefined) return []
  const repository = realpathSync(resolve(dirname(own), common))
  const vaults: string[] = []
  for (const checkout of checkouts) {
    const candidate = join(checkout, path)
    if (!existsSync(join(candidate, 'owner.json')) || realpathSync(candidate) === own) continue
    // A copied .git can still list the original repository's worktrees. They must point back to this repository.
    const other = (await git(checkout, ['rev-parse', '--git-common-dir']))?.trim()
    if (other !== undefined && realpathSync(resolve(checkout, other)) === repository) {
      vaults.push(realpathSync(candidate))
    }
  }
  return vaults
}
