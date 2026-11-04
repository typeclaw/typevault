import { expect, test } from 'bun:test'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { strToU8, zipSync } from 'fflate'

import { importFrom, type ImportSource } from './index'

const cases: readonly {
  readonly source: ImportSource
  readonly text: string | Uint8Array
  readonly name: string
  readonly field: string
}[] = [
  { source: 'dotenv', text: 'API_KEY=hunter2', name: 'api-key', field: '$default' },
  { source: 'typeclaw', text: 'TYPECLAW_SECRET_EXAMPLE=hunter2\nOTHER=ignored', name: 'example', field: '$default' },
  {
    source: 'csv',
    text: 'name,url,username,password\nExample,https://example.com,user@example.com,hunter2',
    name: 'example',
    field: 'password',
  },
  {
    source: 'lastpass',
    text: 'url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,hunter2,Example,,0',
    name: 'example',
    field: '$default',
  },
  {
    source: 'bitwarden',
    text: '{"items":[{"type":2,"name":"Example","notes":"hunter2"}]}',
    name: 'example',
    field: '$default',
  },
  {
    source: '1password',
    text: zipSync({
      'export.data': strToU8(
        JSON.stringify({
          accounts: [
            {
              vaults: [
                {
                  items: [
                    {
                      categoryUuid: '003',
                      overview: { title: 'Example' },
                      details: { notesPlain: 'hunter2' },
                    },
                  ],
                },
              ],
            },
          ],
        }),
      ),
    }),
    name: 'example',
    field: '$default',
  },
]

test.each(cases)('dispatcher reads $source and leaves the source unchanged', async ({ source, text, name, field }) => {
  const directory = await mkdtemp(join(tmpdir(), 'typevault-import-'))
  try {
    const path = join(directory, '.env')
    await writeFile(path, text)
    const before = await readFile(path)
    const result = await importFrom(source, { path: source === 'typeclaw' ? directory : path })
    expect<readonly (readonly string[])[]>(
      result.entries.map((entry) => [entry.name, entry.fields[field]?.type ?? 'missing']),
    ).toEqual([[name, 'secret']])
    expect(await readFile(path)).toEqual(before)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('dispatcher reports missing files and missing KeePass passwords with typed errors', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'typevault-import-'))
  try {
    await expect(importFrom('dotenv', { path: join(directory, 'missing') })).rejects.toMatchObject({
      code: 'not_found',
    })
    await expect(importFrom('keepass', { path: join(directory, 'missing') })).rejects.toMatchObject({ code: 'invalid' })
    await expect(importFrom('csv', { path: directory })).rejects.toMatchObject({ code: 'invalid' })
    await expect(importFrom('dotenv', { path: '' })).rejects.toMatchObject({ code: 'invalid' })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
