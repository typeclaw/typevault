export const styles = `
:root {
  color-scheme: light dark;
  --canvas: #f4f5f2; --surface: #ffffff; --ink: #202c29; --muted: #52635c;
  --line: #82938b; --soft: #eaf0ec; --accent: #235a46; --on-accent: #ffffff;
  --hover: #194735; --error: #a52b32; --focus: #236448;
  font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  scrollbar-color: var(--line) var(--canvas);
}
@media (prefers-color-scheme: dark) {
  :root {
    --canvas: #141b18; --surface: #1e2823; --ink: #edf3ee; --muted: #b3c4b9;
    --line: #7b9183; --soft: #2a3830; --accent: #aad7bb; --on-accent: #14251b;
    --hover: #c4e8d0; --error: #ffabb0; --focus: #aad7bb;
  }
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100dvh; display: grid; place-items: center; padding: 32px 16px;
  background: var(--canvas); color: var(--ink); }
main { width: min(100%, 528px); background: var(--surface); border-radius: 20px; padding: 40px;
  overflow-wrap: anywhere; }
h1 { font-size: 32px; line-height: 1.2; letter-spacing: -.025em; margin: 0 0 12px; }
p { margin: 0; }
.muted, .hint { color: var(--muted); }
.context { display: grid; gap: 8px; margin: 24px 0; }
.reason { white-space: pre-wrap; }
.match { padding: 20px 0; border-block: 1px solid var(--line); margin-bottom: 28px; }
.code { font: 600 28px/1.4 ui-monospace, monospace; letter-spacing: .05em; font-variant-numeric: tabular-nums; }
.hint { font-size: 14px; margin-top: 8px; }
form, #fields { display: grid; gap: 24px; }
.field { display: grid; gap: 8px; }
label { font-weight: 600; }
.input-row { display: flex; gap: 8px; align-items: start; }
input, textarea { width: 100%; min-width: 0; min-height: 48px; border: 1px solid var(--line);
  border-radius: 8px; padding: 12px; background: var(--surface); color: var(--ink); font: inherit;
  caret-color: var(--accent); }
textarea { min-height: 144px; resize: vertical; }
.concealed { -webkit-text-security: disc; }
button { min-height: 48px; border: 0; border-radius: 8px; padding: 12px 16px; cursor: pointer;
  font: 600 16px/1.5 system-ui, sans-serif; color: var(--on-accent); background: var(--accent); }
button:hover { background: var(--hover); }
button:active { opacity: .85; }
button:disabled { cursor: default; opacity: .65; }
.toggle { width: 80px; flex-shrink: 0; background: var(--soft); color: var(--ink); }
.toggle:hover { background: var(--canvas); }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 3px; }
::selection { background: var(--accent); color: var(--on-accent); }
#submit { width: 100%; }
#status { color: var(--error); }
#status:empty { display: none; }
#success { margin-top: 24px; }
[hidden] { display: none !important; }
@media (max-width: 480px) {
  body { padding: 16px; }
  main { padding: 28px 24px; border-radius: 16px; }
}
`
