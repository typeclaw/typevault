import { afterAll, expect, test } from 'bun:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const SCRIPT = join(import.meta.dir, 'carries-release-notes.ts')
const dir = mkdtempSync(join(tmpdir(), 'release-notes-'))
const note = join(dir, 'note.md')
writeFileSync(note, '**Upgrade first.** Older releases cannot read this.\nUpgrade every client before storing one.\n')

afterAll(() => rmSync(dir, { recursive: true, force: true }))

// Runs the script the way the Release workflow does: the note file as the argument, the release body on stdin.
async function carries(body: string): Promise<boolean> {
  const proc = Bun.spawn([process.execPath, SCRIPT, note], {
    stdin: new Blob([body]),
    stdout: 'ignore',
    stderr: 'ignore',
  })
  return (await proc.exited) === 0
}

test.each([
  [
    'both lines together, above the generated notes',
    "**Upgrade first.** Older releases cannot read this.\nUpgrade every client before storing one.\n\n## What's Changed",
    true,
  ],
  [
    'both lines with CRLF line endings',
    '**Upgrade first.** Older releases cannot read this.\r\nUpgrade every client before storing one.\r\n',
    true,
  ],
  ['only the first line', "**Upgrade first.** Older releases cannot read this.\n\n## What's Changed", false],
  [
    'both lines, split by other text',
    '**Upgrade first.** Older releases cannot read this.\n* a change\nUpgrade every client before storing one.',
    false,
  ],
  ['no note at all', "## What's Changed", false],
])('a release body with %s carries the note: %p', async (_, body, expected) => {
  expect(await carries(body)).toBe(expected)
})
