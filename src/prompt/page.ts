import { createHash } from 'node:crypto'

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
    entrypoints: [new URL('./browser.ts', import.meta.url).pathname],
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
<h1>${escapeHtml(view.name)}</h1>
<p class="muted">Readable by: ${escapeHtml(view.tier)}</p>
<div class="context"><p class="reason">${escapeHtml(view.reason)}</p>
<p class="muted">Requested by: ${escapeHtml(view.requester)}</p></div>
<section class="match" aria-label="Match code"><p class="code">${escapeHtml(view.code)}</p>
<p class="hint">Compare this code with the one in your chat before entering a secret.</p></section>
<form id="prompt"><div id="fields"></div>
<p class="hint">Encrypted in your browser. Only the selected tier's recipients can read this secret.</p>
<button id="submit" type="submit">Encrypt and submit</button>
<p id="status" role="alert"></p></form>
<section id="success" hidden role="status" tabindex="-1"><h2>Secret submitted</h2>
<p>Your encrypted secret was delivered. You can close this page.</p></section>
<noscript>JavaScript is required to encrypt your secret before it leaves this browser.</noscript>
<script type="application/json" id="tv-data">${data}</script><script type="module">${script}</script>`,
  )
}

export function expiredPage(): string {
  return shell(
    'Request unavailable',
    `<h1>Expired or already used</h1>
<p>This one-time request is no longer available. Ask the agent for a new link and match code.</p>`,
  )
}
