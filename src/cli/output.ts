export const print = (text: string): void => {
  process.stdout.write(text.endsWith('\n') ? text : `${text}\n`)
}

export const note = (text: string): void => {
  process.stderr.write(`${text}\n`)
}

/** Left-aligned columns, no borders: readable by people and by `awk`. */
export function table(rows: readonly (readonly string[])[]): string {
  const widths = rows.reduce<number[]>(
    (acc, row) => row.map((cell, index) => Math.max(acc[index] ?? 0, Bun.stringWidth(cell))),
    [],
  )
  return rows
    .map((row) =>
      row
        .map((cell, index) =>
          index === row.length - 1 ? cell : cell + ' '.repeat((widths[index] ?? 0) - Bun.stringWidth(cell)),
        )
        .join('  '),
    )
    .join('\n')
}

export const csv = (value: string | undefined): readonly string[] =>
  value === undefined || value === ''
    ? []
    : value
        .split(',')
        .map((item) => item.trim())
        .filter((item) => item !== '')

/** Every value of a repeatable `--flag value` / `--flag=value` in raw argv. */
export function repeated(rawArgs: readonly string[], flag: string): readonly string[] {
  const values: string[] = []
  rawArgs.forEach((arg, index) => {
    if (arg === flag) {
      const next = rawArgs[index + 1]
      if (next !== undefined) values.push(next)
    } else if (arg.startsWith(`${flag}=`)) values.push(arg.slice(flag.length + 1))
  })
  return values
}

export async function readStdin(): Promise<string> {
  return (await Bun.stdin.text()).replace(/\r?\n$/, '')
}
