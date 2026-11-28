// Exits 0 when the release body on stdin contains the whole note file named by the argument, as one block, and 10
// when it doesn't. Any other exit is a failure to check, never an answer. The Release workflow uses it to tell
// whether a GitHub release carries its committed release note.

export const NOT_CARRIED = 10

const normalized = (text: string): string => text.replaceAll('\r\n', '\n').trim()

export function carriesNote(note: string, body: string): boolean {
  const wanted = normalized(note)
  return wanted !== '' && normalized(body).includes(wanted)
}

if (import.meta.main) {
  const [path] = process.argv.slice(2)
  if (path === undefined) throw new Error('usage: carries-release-notes.ts <note.md> < body')
  process.exit(carriesNote(await Bun.file(path).text(), await Bun.stdin.text()) ? 0 : NOT_CARRIED)
}
