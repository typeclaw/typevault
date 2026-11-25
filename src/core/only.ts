import { type EntryName, entryPattern } from './naming'

/** True when `name` matches any `--only` pattern (exact names or globs such as `github/*`). */
export function matchesOnly(name: EntryName, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => new Bun.Glob(entryPattern(pattern)).match(name))
}
