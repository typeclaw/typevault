import { TypeVaultError } from '../core/errors'

export type Passwords = { readonly ask: (question: string) => Promise<string> }

let fromStdin = false
let stdinLines: Promise<string[]> | undefined
let nextLine = 0

/** Set by the global `--vault-password-stdin` flag: passwords are read from stdin, one per line, instead of a terminal. */
export function readPasswordsFromStdin(): void {
  fromStdin = true
}

export const passwordsFromStdin = (): boolean => fromStdin

export function passwords(): Passwords {
  if (!fromStdin) return { ask: promptHidden }
  return {
    ask: async () => {
      stdinLines ??= Bun.stdin.text().then((text) => text.split(/\r?\n/))
      const line = (await stdinLines)[nextLine++]
      if (line === undefined || line === '')
        throw new TypeVaultError('invalid', '--vault-password-stdin needs one password per line')
      return line
    },
  }
}

/** A new password: asked twice on a terminal so a typo can't lock the owner out. */
export async function newPassword(source: Passwords): Promise<string> {
  const password = await source.ask('New password: ')
  if (!fromStdin && (await source.ask('Repeat it: ')) !== password) {
    throw new TypeVaultError('invalid', 'the passwords do not match')
  }
  return password
}

export async function promptHidden(question: string): Promise<string> {
  const { stdin, stderr } = process
  if (!stdin.isTTY) {
    throw new TypeVaultError(
      'locked',
      'no terminal to ask for your TypeVault password (pass --vault-password-stdin to pipe it)',
    )
  }
  stderr.write(question)
  stdin.setRawMode(true)
  stdin.resume()
  const { promise, resolve, reject } = Promise.withResolvers<string>()
  let typed = ''
  const finish = (): void => {
    stdin.off('data', onData)
    stdin.setRawMode(false)
    stdin.pause()
    stderr.write('\n')
  }
  const onData = (chunk: Buffer): void => {
    for (const char of chunk.toString('utf8')) {
      if (char === '\r' || char === '\n') {
        finish()
        resolve(typed)
        return
      }
      if (char === '\u0003') {
        finish()
        reject(new TypeVaultError('invalid', 'cancelled'))
        return
      }
      typed = char === '\u007f' || char === '\b' ? [...typed].slice(0, -1).join('') : typed + char
    }
  }
  stdin.on('data', onData)
  return promise
}
