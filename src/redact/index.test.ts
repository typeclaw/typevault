import { describe, expect, it } from 'bun:test'

import { TypeVaultError } from '../core/errors'
import { createRedactor } from './index'
import type { Redactor } from './index'

const secret = 'abc?~>"\n\\é'
const encoded = Buffer.from(secret).toString('base64')
const url = encoded.replaceAll('+', '-').replaceAll('/', '_')
const variants: readonly string[] = [
  secret,
  encoded,
  encoded.replace(/=+$/, ''),
  url,
  url.replace(/=+$/, ''),
  encodeURIComponent(secret),
  JSON.stringify(secret).slice(1, -1),
]

async function streamChunks(redactor: Redactor, chunks: readonly Uint8Array[]): Promise<string> {
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk)
      controller.close()
    },
  })
  return new Response(source.pipeThrough(redactor.stream())).text()
}

describe('createRedactor', () => {
  it.each(variants)('redacts variant %p', (variant) => {
    // Given
    const redactor = createRedactor([secret, secret])
    // When
    const output = redactor.redact(`before ${variant} after ${variant}`)
    // Then
    expect(output).toBe('before [redacted] after [redacted]')
  })

  it('ignores short values and their encoded variants', () => {
    // Given
    const redactor = createRedactor(['', 'a', 'ab', 'abc', '🔑🔒🔐'])
    const text = 'a ab abc YWJj abc%20 🔑🔒🔐'
    // When
    const output = redactor.redact(text)
    // Then
    expect(output).toBe(text)
  })

  it('redacts four character values', () => {
    // Given
    const redactor = createRedactor(['abcd'])
    // When
    const output = redactor.redact('abcd')
    // Then
    expect(output).toBe('[redacted]')
  })

  it('prefers the longest match at the same position', () => {
    // Given
    const redactor = createRedactor(['abcd', 'abcdef', 'bcde'])
    // When
    const output = redactor.redact('abcdef abcd bcde')
    // Then
    expect(output).toBe('[redacted] [redacted] [redacted]')
  })

  it('treats patterns and replacement as literal strings without rescanning', () => {
    // Given
    const redactor = createRedactor(['a.*$', 'abcd'], { replacement: '$&abcd' })
    // When
    const output = redactor.redact('a.*$ abcd axxx')
    // Then
    expect(output).toBe('$&abcd $&abcd axxx')
  })

  it('rejects malformed Unicode with a typed error', () => {
    // Given
    const values = ['abcd\ud800']
    // When / Then
    expect(() => createRedactor(values)).toThrow(TypeVaultError)
  })
})

describe('stream', () => {
  it.each(variants)('redacts %p at every possible byte boundary', async (variant) => {
    // Given
    const redactor = createRedactor([secret])
    const bytes = new TextEncoder().encode(`before ${variant} after`)
    // When
    const outputs = await Promise.all(
      Array.from({ length: bytes.length + 1 }, (_, boundary) =>
        streamChunks(redactor, [bytes.slice(0, boundary), bytes.slice(boundary)]),
      ),
    )
    // Then
    expect(outputs).toEqual(Array.from({ length: bytes.length + 1 }, () => 'before [redacted] after'))
  })

  it('preserves multibyte text while redacting one byte chunks and flushing a trailing secret', async () => {
    // Given
    const redactor = createRedactor(['🔐café'])
    const bytes = new TextEncoder().encode('😀 before 🔐café / 終 🔐café')
    // When
    const output = await streamChunks(
      redactor,
      Array.from(bytes, (byte) => Uint8Array.of(byte)),
    )
    // Then
    expect(output).toBe('😀 before [redacted] / 終 [redacted]')
  })

  it('retains incomplete matches instead of emitting secret fragments', async () => {
    // Given
    const stream = createRedactor(['abcdefgh']).stream()
    const reader = stream.readable.getReader()
    const writer = stream.writable.getWriter()
    const first = reader.read()
    // When
    await writer.write(new TextEncoder().encode('safe abcdefg'))
    const emitted = await first
    const tail = new Response(
      new ReadableStream<Uint8Array>({
        async pull(controller) {
          const result = await reader.read()
          if (result.done) controller.close()
          else controller.enqueue(result.value)
        },
      }),
    ).text()
    await writer.write(new TextEncoder().encode('h'))
    await writer.close()
    // Then
    expect(new TextDecoder().decode(emitted.value)).toBe('safe ')
    expect(await tail).toBe('[redacted]')
  })

  it('keeps longest matches and replacement semantics across chunks', async () => {
    // Given
    const redactor = createRedactor(['abcd', 'abcdef'], { replacement: 'abcd' })
    // When
    const output = await streamChunks(
      redactor,
      ['abc', 'def ab', 'cd'].map((text) => new TextEncoder().encode(text)),
    )
    // Then
    expect(output).toBe('abcd abcd')
  })

  it('is identity for an empty value list including UTF-8 BOM', async () => {
    // Given
    const redactor = createRedactor([])
    const text = '\ufeff😀 unchanged'
    // When
    const output = redactor.redact(text)
    const bytes = await new Response(
      new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(redactor.stream()),
    ).arrayBuffer()
    // Then
    expect(output).toBe(text)
    expect(new Uint8Array(bytes)).toEqual(new TextEncoder().encode(text))
  })

  it('preserves arbitrary bytes around secrets at every boundary', async () => {
    const input = Buffer.concat([
      Buffer.from([0xff, 0xfe, 0]),
      Buffer.from('dummy-value-0001'),
      Buffer.from([0x80, 0xc3]),
    ])
    const expected = Buffer.concat([Buffer.from([0xff, 0xfe, 0]), Buffer.from('[redacted]'), Buffer.from([0x80, 0xc3])])
    for (let boundary = 0; boundary <= input.length; boundary++) {
      const source = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(input.subarray(0, boundary))
          controller.enqueue(input.subarray(boundary))
          controller.close()
        },
      })
      const result = await new Response(source.pipeThrough(createRedactor(['dummy-value-0001']).stream())).arrayBuffer()
      expect(Buffer.from(result)).toEqual(expected)
    }
  })

  it('emits a prompt before the next input arrives', async () => {
    const stream = createRedactor(['dummy-value-0001', 'x'.repeat(3000)]).stream()
    const reader = stream.readable.getReader()
    const writer = stream.writable.getWriter()
    try {
      const output = reader.read()
      await writer.write(Buffer.from('Enter name: '))
      const result = await output
      expect(Buffer.from(result.value ?? []).toString()).toBe('Enter name: ')
    } finally {
      await reader.cancel()
      await writer.close().catch((error: unknown) => {
        if (!(error instanceof TypeError)) throw error
      })
    }
  }, 2000)

  it('retains a complete shorter match until a longer variant is decided', async () => {
    expect(await streamChunks(createRedactor(['abcd', 'abcdef']), [Buffer.from('abcd'), Buffer.from('ef!')])).toBe(
      '[redacted]!',
    )
  })
})
