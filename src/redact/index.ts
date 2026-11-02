import { toBase64, toBase64Url, utf8 } from '../core/encoding'
import { TypeVaultError } from '../core/errors'

export { scrubFile } from './scrub-file'

export type Redactor = {
  readonly redact: (text: string) => string
  readonly stream: () => TransformStream<Uint8Array, Uint8Array>
}

export function createRedactor(values: readonly string[], options?: { readonly replacement?: string }): Redactor {
  const variants = new Set<string>()
  for (const value of values) {
    if (Array.from(value).length < 4) continue
    const bytes = utf8(value)
    const standard = toBase64(bytes)
    const url = toBase64Url(bytes)
    variants.add(value)
    variants.add(standard)
    variants.add(standard.replace(/=+$/, ''))
    variants.add(url)
    variants.add(url.padEnd(Math.ceil(url.length / 4) * 4, '='))
    variants.add(JSON.stringify(value).slice(1, -1))
    try {
      variants.add(encodeURIComponent(value))
    } catch (error) {
      if (error instanceof URIError) {
        throw new TypeVaultError('invalid', 'Secret contains invalid Unicode')
      }
      throw new TypeVaultError('invalid', 'Could not encode secret')
    }
  }
  const patterns: readonly string[] = [...variants].sort((left, right) => right.length - left.length)
  const longest = patterns[0]?.length ?? 1
  const replacement = options?.replacement ?? '[redacted]'

  // Consume whole matches, even when they extend beyond the safe emission boundary.
  const consume = (text: string, limit: number): { readonly output: string; readonly rest: string } => {
    let index = 0
    let output = ''
    while (index < limit) {
      const match = patterns.find((pattern) => text.startsWith(pattern, index))
      if (match !== undefined) {
        output += replacement
        index += match.length
      } else {
        const point = text.codePointAt(index)
        const width = point !== undefined && point > 0xffff ? 2 : 1
        output += text.slice(index, index + width)
        index += width
      }
    }
    return { output, rest: text.slice(index) }
  }

  return {
    redact: (text) => consume(text, text.length).output,
    stream: () => {
      const decoder = new TextDecoder('utf-8', { ignoreBOM: true })
      const encoder = new TextEncoder()
      let pending = ''
      return new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          pending += decoder.decode(chunk, { stream: true })
          const limit = Math.max(0, pending.length - longest + 1)
          const result = consume(pending, limit)
          pending = result.rest
          if (result.output.length > 0) controller.enqueue(encoder.encode(result.output))
        },
        flush(controller) {
          pending += decoder.decode()
          const result = consume(pending, pending.length)
          if (result.output.length > 0) controller.enqueue(encoder.encode(result.output))
        },
      })
    },
  }
}
