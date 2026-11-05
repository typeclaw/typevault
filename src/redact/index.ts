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
  const replacement = options?.replacement ?? '[redacted]'
  const bytePatterns = patterns.map((pattern) => Buffer.from(pattern)).sort((left, right) => right.length - left.length)
  const replacementBytes = Buffer.from(replacement)
  const expansion = Math.max(1, ...bytePatterns.map((pattern) => replacementBytes.length / pattern.length))

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
      let pending = Buffer.alloc(0)
      const emit = (input: Buffer, final: boolean, controller: TransformStreamDefaultController<Uint8Array>) => {
        let limit = input.length
        if (!final) {
          for (const pattern of bytePatterns) {
            const start = Math.max(0, input.length - pattern.length + 1)
            for (let index = input.indexOf(pattern.subarray(0, 1), start); index >= 0 && index < limit;) {
              if (input.subarray(index).equals(pattern.subarray(0, input.length - index))) {
                limit = index
                break
              }
              index = input.indexOf(pattern.subarray(0, 1), index + 1)
            }
          }
        }
        let index = 0
        const output = Buffer.allocUnsafe(Math.ceil(input.length * expansion))
        let written = 0
        const matches = bytePatterns.map((pattern) => ({ pattern, at: input.indexOf(pattern) }))
        while (index < limit) {
          let next = input.length
          let match: Buffer | undefined
          for (const candidate of matches) {
            if (candidate.at >= 0 && candidate.at < index) candidate.at = input.indexOf(candidate.pattern, index)
            if (candidate.at >= 0 && candidate.at < next) {
              next = candidate.at
              match = candidate.pattern
            }
          }
          if (match === undefined || next >= limit) {
            written += input.copy(output, written, index, limit)
            index = limit
          } else {
            written += input.copy(output, written, index, next)
            written += replacementBytes.copy(output, written)
            index = next + match.length
          }
        }
        if (written > 0) controller.enqueue(output.subarray(0, written))
        // Copy only the undecided suffix, so it cannot retain a large input buffer.
        pending = Buffer.from(input.subarray(index))
      }
      return new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          const input = pending.length > 0 ? Buffer.concat([pending, chunk]) : Buffer.from(chunk)
          emit(input, false, controller)
        },
        flush(controller) {
          emit(pending, true, controller)
        },
      })
    },
  }
}
