import { afterAll, describe, expect, test } from 'bun:test'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, dirname, join } from 'node:path'

const SCRIPT = join(import.meta.dir, 'publish-github-release.sh')
const NOTE = '**Upgrade first.** Older releases cannot read this.'
const root = mkdtempSync(join(tmpdir(), 'publish-release-'))
const project = join(root, 'project')
const bin = join(root, 'bin')
const log = join(root, 'gh.log')
mkdirSync(join(project, '.github', 'release-notes'), { recursive: true })
writeFileSync(join(project, '.github', 'release-notes', '0.8.0.md'), `${NOTE}\n`)
mkdirSync(bin)
// A `gh` that records each call and answers `release view` from RELEASE (none, or a JSON release).
writeFileSync(
  join(bin, 'gh'),
  `#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
if [ "$1 $2" = "release view" ]; then
  [ "$RELEASE" = none ] && exit 1
  printf '%s\\n' "$RELEASE"
fi
`,
)
chmodSync(join(bin, 'gh'), 0o755)

afterAll(() => rmSync(root, { recursive: true, force: true }))

const brokenBun = join(root, 'broken-bun')
mkdirSync(brokenBun)
writeFileSync(join(brokenBun, 'bun'), '#!/usr/bin/env bash\nexit 1\n')
chmodSync(join(brokenBun, 'bun'), 0o755)

async function publish(
  version: string,
  release: { isDraft: boolean; body: string } | undefined,
  options: { bunBreaks?: boolean } = {},
): Promise<{ code: number; calls: string[] }> {
  writeFileSync(log, '')
  const bunDirs = options.bunBreaks ? [brokenBun] : [dirname(process.execPath)]
  const proc = Bun.spawn(['bash', SCRIPT, version], {
    cwd: project,
    env: {
      ...process.env,
      PATH: [bin, ...bunDirs, process.env['PATH'] ?? ''].join(delimiter),
      GH_LOG: log,
      RELEASE: release === undefined ? 'none' : JSON.stringify(release),
    },
    stdout: 'ignore',
    stderr: 'ignore',
  })
  const code = await proc.exited
  const calls = readFileSync(log, 'utf8')
    .split('\n')
    .filter((line) => line !== '' && !line.startsWith('release view'))
  return { code, calls }
}

// The script is bash and the stub a POSIX executable, as on the Linux runner that publishes.
describe.skipIf(process.platform === 'win32')('publish-github-release.sh', () => {
  test('creates a missing release with its committed note above the generated notes', async () => {
    expect(await publish('0.8.0', undefined)).toEqual({
      code: 0,
      calls: ['release create 0.8.0 --verify-tag --generate-notes --notes-file .github/release-notes/0.8.0.md'],
    })
  })

  test('leaves an already complete release alone, without editing it', async () => {
    expect(await publish('0.8.0', { isDraft: false, body: `${NOTE}\n\n## What's Changed` })).toEqual({
      code: 0,
      calls: [],
    })
  })

  test.each([
    ['a draft without its note', { isDraft: true, body: "## What's Changed" }],
    ['a public release without its note', { isDraft: false, body: "## What's Changed" }],
  ])('adds the note to %s and publishes it', async (_, release) => {
    const { code, calls } = await publish('0.8.0', release)
    expect(code).toBe(0)
    expect(calls).toHaveLength(1)
    expect(calls[0]).toMatch(/^release edit 0\.8\.0 --notes-file \S+ --draft=false$/)
  })

  test('publishes a draft that already carries its note, without rewriting it', async () => {
    expect(await publish('0.8.0', { isDraft: true, body: `${NOTE}\n\n## What's Changed` })).toEqual({
      code: 0,
      calls: ['release edit 0.8.0 --draft=false'],
    })
  })

  test('fails without touching a complete release when the note check cannot run', async () => {
    const { code, calls } = await publish('0.8.0', { isDraft: false, body: `${NOTE}` }, { bunBreaks: true })
    expect(code).not.toBe(0)
    expect(calls).toEqual([])
  })

  test('creates a release with no committed note from the generated notes alone', async () => {
    expect(await publish('0.8.1', undefined)).toEqual({
      code: 0,
      calls: ['release create 0.8.1 --verify-tag --generate-notes'],
    })
  })
})
