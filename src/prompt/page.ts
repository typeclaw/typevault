import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

import { TypeVaultError } from '../core/errors'
import { styles } from './styles'
import type { PromptView } from './types'

let cachedAssets: ReturnType<typeof buildAssets> | undefined

export function pageAssets(): ReturnType<typeof buildAssets> {
  cachedAssets ??= buildAssets()
  return cachedAssets
}

async function buildAssets() {
  const result = await Bun.build({
    entrypoints: [fileURLToPath(new URL('./browser.ts', import.meta.url))],
    target: 'browser',
    minify: true,
  })
  const output = result.outputs[0]
  if (!result.success || output === undefined) {
    throw new TypeVaultError('unavailable', 'Unable to build prompt browser script')
  }
  const script = (await output.text()).replace(/<\/script/gi, '<\\/script')
  const hash = (value: string): string => createHash('sha256').update(value).digest('base64')
  return {
    script,
    headers: {
      'Content-Security-Policy': `default-src 'none'; script-src 'sha256-${hash(script)}'; style-src 'sha256-${hash(styles)}'; connect-src 'self'; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'`,
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  }
}

const LOCK_ICON =
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>'
const CHECK_ICON =
  '<svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m8 12.5 2.5 2.5L16 9.5"/></svg>'

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    const entities: Readonly<Record<string, string>> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }
    return entities[char] ?? char
  })
}

function shell(title: string, content: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark"><title>${escapeHtml(title)} | typevault</title>
<style>${styles}</style></head><body><main>${content}</main></body></html>`
}

export function promptPage(view: PromptView, script: string): string {
  const data = JSON.stringify(view).replace(/</g, '\\u003c')
  return shell(
    'Secret request',
    `
<header><p class="eyebrow">Secret request</p>
<h1>${escapeHtml(view.name)}</h1>
<p class="reason">${escapeHtml(view.reason)}</p>
<dl class="meta"><div><dt>Requested by</dt><dd>${escapeHtml(view.requester)}</dd></div>
<div><dt>Readable by</dt><dd>${escapeHtml(view.tier)}</dd></div></dl></header>
<section class="match" aria-label="Match code"><div class="match-text"><p class="match-label">Match code</p>
<p class="hint">Make sure your chat shows the same code.</p></div>
<p class="code">${escapeHtml(view.code)}</p></section>
<form id="prompt"><div id="fields"></div>
<div class="actions"><p id="status" role="alert"></p>
<button id="submit" type="submit">Encrypt and submit</button>
<p class="note">${LOCK_ICON}<span>Encrypted in your browser. Only the selected tier's recipients can read this secret.</span></p></div></form>
<section id="success" class="done" hidden role="status" tabindex="-1">${CHECK_ICON}<h2>Secret submitted</h2>
<p>Your encrypted secret was delivered. You can close this page.</p></section>
<noscript>JavaScript is required to encrypt your secret before it leaves this browser.</noscript>
<script type="application/json" id="tv-data">${data}</script><script type="module">${script}</script>`,
  )
}

export function expiredPage(): string {
  return shell(
    'Request unavailable',
    `<p class="eyebrow">Secret request</p><h1>Expired or already used</h1>
<p class="reason">This one-time request is no longer available. Ask the agent for a new link and match code.</p>`,
  )
}
