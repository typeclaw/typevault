import { describe, expect, it } from 'bun:test'

import { parseEntryName } from '../core/naming'
import { envFor, resolveEnvRefs } from './env'
import type { EntryValue } from './types'

const value: EntryValue = {
  id: 'entry',
  name: parseEntryName('service'),
  tier: 'default',
  rev: 1,
  tags: [],
  created: '2026-01-01T00:00:00Z',
  rotated: '2026-01-01T00:00:00Z',
  needsRotation: false,
  fields: { $default: { type: 'secret', value: 'dummy-secret' } },
}
const now = new Date(0)
const policy = { ownTiers: ['default'], explicit: [] }
const unsafe = [
  'CURL_HOME',
  'WGETRC',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'NODE_EXTRA_CA_CERTS',
  'CLASSPATH',
  'GEM_PATH',
  'GEM_HOME',
  'SSLKEYLOGFILE',
  'FTP_PROXY',
  'RSYNC_PROXY',
  'SOCKS_SERVER',
  'AWS_CA_BUNDLE',
  'NIX_SSL_CERT_FILE',
  'GCONV_PATH',
  'SERVICE_PROXY',
  'SERVICE_CA_BUNDLE',
  'SERVICE_CA_CERTS',
  'SERVICE_CERT_FILE',
  'SERVICECERT_FILE',
] as const
const ordinary = [
  'SMART_HOME',
  'CUSTOMER_HOME',
  'PROXY_API_KEY',
  'SERVICE_PROXY_PASSWORD',
  'SERVICE_CA_BUNDLE_TOKEN',
  'SERVICE_CA_CERTS_TOKEN',
  'SERVICE_CERT_FILE_PASSWORD',
] as const

describe('run environment safety (#59)', () => {
  it.each(unsafe)('omits the derived variable %s', (variable) => {
    const name = parseEntryName(variable.toLowerCase().replaceAll('_', '-'))
    expect(envFor([{ ...value, name }], now, policy)).toEqual({})
  })

  it.each(['PROXY', 'CA_BUNDLE', 'CA_CERTS', 'CERT_FILE'])(
    'omits a reserved suffix derived from a named field %s',
    (field) => {
      expect(
        envFor([{ ...value, fields: { [field]: { type: 'secret', value: 'dummy-secret' } } }], now, policy),
      ).toEqual({})
    },
  )

  it.each(unsafe.flatMap((variable) => [variable, variable.toLowerCase()]))(
    'refuses an explicit reference in %s before reading the entry',
    async (variable) => {
      const reads: string[] = []
      const get = async (name: string) => {
        reads.push(name)
        return value
      }
      await expect(resolveEnvRefs({ [variable]: 'typevault://service' }, get, now)).rejects.toMatchObject({
        code: 'invalid',
      })
      expect(reads).toEqual([])
    },
  )

  it.each(ordinary)('loads the ordinary derived variable %s', (variable) => {
    const name = parseEntryName(variable.toLowerCase().replaceAll('_', '-'))
    expect(envFor([{ ...value, name }], now, policy)).toEqual({ [variable]: 'dummy-secret' })
  })

  it.each(ordinary)('resolves an ordinary explicit reference in %s', async (variable) => {
    const resolved = await resolveEnvRefs({ [variable]: 'typevault://service' }, async () => value, now)
    expect(resolved.env).toEqual({ [variable]: 'dummy-secret' })
  })
})
