import { describe, expect, it } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { parseTotpSeed, totpCode, totpRemainingSeconds, type TotpAlgorithm } from './totp'

const rfcSecret = '12345678901234567890'
const secrets = {
  SHA1: rfcSecret,
  SHA256: `${rfcSecret}123456789012`,
  SHA512: `${rfcSecret}${rfcSecret}${rfcSecret}1234`,
} as const

describe('totpCode RFC 6238 Appendix B', () => {
  // All six timestamps and all three hash algorithms from Appendix B.
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ] as const

  it.each(vectors)('matches all algorithms at %p seconds', (seconds, sha1, sha256, sha512) => {
    const expected: Readonly<Record<TotpAlgorithm, string>> = { SHA1: sha1, SHA256: sha256, SHA512: sha512 }
    for (const algorithm of ['SHA1', 'SHA256', 'SHA512'] as const) {
      const params = {
        secret: new TextEncoder().encode(secrets[algorithm]),
        digits: 8,
        period: 30,
        algorithm,
      } as const
      expect(totpCode(params, new Date(seconds * 1000))).toBe(expected[algorithm])
    }
  })

  it.each([
    [6, '081804'],
    [7, '7081804'],
  ] as const)('supports %p digits with zero padding', (digits, expected) => {
    const params = { ...parseTotpSeed('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), digits }
    expect(totpCode(params, new Date(1111111109000))).toBe(expected)
  })

  it('uses the configured period and floors fractional seconds', () => {
    const params = { ...parseTotpSeed('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), digits: 8, period: 60 } as const
    expect(totpCode(params, new Date(119999))).toBe('94287082')
  })
})

describe('parseTotpSeed', () => {
  it.each(['MZXW6===', 'mzxw6', ' mz xw6 '])('decodes padded or normalized base32 %p', (seed) => {
    expect(parseTotpSeed(seed)).toEqual({
      secret: new TextEncoder().encode('foo'),
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
    })
  })

  it('uses defaults for otpauth TOTP URIs', () => {
    expect(parseTotpSeed('otpauth://totp/Example:alice?secret=MZXW6')).toEqual(parseTotpSeed('MZXW6'))
  })

  it('parses explicit URI options', () => {
    expect(parseTotpSeed('otpauth://totp/Example?secret=mz%20xw6&digits=7&period=45&algorithm=sha512')).toEqual({
      secret: new TextEncoder().encode('foo'),
      digits: 7,
      period: 45,
      algorithm: 'SHA512',
    })
  })

  it.each([
    '',
    '   ',
    'secret-with-invalid-characters',
    'A',
    'MZ',
    'MZX=W6',
    'otpauth://hotp/Example?secret=MZXW6',
    'otpauth://totp/Example',
    'otpauth://totp/?secret=MZXW6',
    'otpauth://',
    ...['digits=5', 'digits=9', 'period=0', 'period=-1', 'period=1.5', 'period=NaN', 'algorithm=MD5'].map(
      (option) => `otpauth://totp/Example?secret=MZXW6&${option}`,
    ),
  ])('rejects malformed seeds without disclosing them: %p', (seed) => {
    expect(() => parseTotpSeed(seed)).toThrow(TypeVaultError)
    try {
      parseTotpSeed(seed)
    } catch (error) {
      expect(error).toBeInstanceOf(TypeVaultError)
      if (!(error instanceof TypeVaultError)) throw error
      expect(error.code).toBe('invalid')
      expect(error.message).not.toContain('MZXW6')
      if (seed) expect(error.message).not.toContain(seed)
    }
  })
})

describe('totpRemainingSeconds', () => {
  it.each([
    [0, 30],
    [1, 30],
    [1000, 29],
    [29999, 1],
    [30000, 30],
  ])('reports remaining whole seconds at %p milliseconds', (milliseconds, expected) => {
    expect(totpRemainingSeconds(parseTotpSeed('MZXW6'), new Date(milliseconds))).toBe(expected)
  })

  it('respects a custom period', () => {
    expect(totpRemainingSeconds({ ...parseTotpSeed('MZXW6'), period: 45 }, new Date(59000))).toBe(31)
  })

  it.each([new Date(-1), new Date(NaN)])('rejects invalid or pre-epoch times: %p', (at) => {
    const params = parseTotpSeed('MZXW6')
    expect(() => totpCode(params, at)).toThrow(TypeVaultError)
    expect(() => totpRemainingSeconds(params, at)).toThrow(TypeVaultError)
  })
})
