import { base64, base64urlnopad } from '@scure/base'

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

export const utf8 = (text: string): Uint8Array => encoder.encode(text)
export const fromUtf8 = (bytes: Uint8Array): string => decoder.decode(bytes)

export const toBase64 = (bytes: Uint8Array): string => base64.encode(bytes)
export const fromBase64 = (text: string): Uint8Array => base64.decode(text)
export const toBase64Url = (bytes: Uint8Array): string => base64urlnopad.encode(bytes)
export const fromBase64Url = (text: string): Uint8Array => base64urlnopad.decode(text)

export type Json = null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json }

/** JSON with object keys sorted recursively, so equal values always serialize to equal bytes. */
const isJsonArray = (value: Json): value is readonly Json[] => Array.isArray(value)

export function canonicalJson(value: Json): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (isJsonArray(value)) return `[${value.map((item: Json) => canonicalJson(item)).join(',')}]`
  const record: { readonly [key: string]: Json } = value
  const keys = Object.keys(record).sort()
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key] ?? null)}`).join(',')}}`
}
