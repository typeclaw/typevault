export const styles = `
:root {
  color-scheme: light dark;
  --canvas: #f5f6fa; --surface: #ffffff; --ink: #141a2e; --muted: #575f7c;
  --line: #e1e6f4; --field: #8d98c4; --soft: #f1f3fa; --accent: #4f5ed7; --on-accent: #ffffff;
  --hover: #3f4ec4; --error: #b42335; --error-soft: #fcf0f1; --focus: #4f5ed7;
  --ring: rgb(79 94 215 / .18); --shadow: 0 1px 2px rgb(13 23 54 / .05), 0 12px 32px rgb(13 23 54 / .08);
  font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  scrollbar-color: var(--field) var(--canvas);
}
@media (prefers-color-scheme: dark) {
  :root {
    --canvas: #0a0f1f; --surface: #121a31; --ink: #eef1fb; --muted: #a9b2d6;
    --line: #232d4d; --field: #4d5d9e; --soft: #1a2343; --accent: #9da7d2; --on-accent: #0d1736;
    --hover: #c3cae6; --error: #ffabb5; --error-soft: #3a1d2a; --focus: #9da7d2;
    --ring: rgb(157 167 210 / .22); --shadow: 0 1px 2px rgb(0 0 0 / .3), 0 12px 32px rgb(0 0 0 / .3);
  }
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100dvh; display: grid; place-items: center; padding: 40px 16px;
  background: var(--canvas); color: var(--ink); -webkit-font-smoothing: antialiased; }
main { width: min(100%, 480px); background: var(--surface); border: 1px solid var(--line);
  border-radius: 20px; padding: 36px; box-shadow: var(--shadow); overflow-wrap: anywhere; }
h1 { font-size: 26px; line-height: 1.25; letter-spacing: -.02em; margin: 0; }
h2 { font-size: 20px; line-height: 1.3; margin: 0 0 6px; }
p { margin: 0; }
.eyebrow { font-size: 13px; font-weight: 600; letter-spacing: .06em; text-transform: uppercase;
  color: var(--accent); margin-bottom: 6px; }
.reason { white-space: pre-wrap; margin-top: 12px; }
.meta { display: flex; flex-wrap: wrap; gap: 4px 24px; margin: 16px 0 0; font-size: 14px; }
.meta div { display: flex; gap: 6px; min-width: 0; }
.meta dt { color: var(--muted); }
.meta dd { margin: 0; font-weight: 500; }
.match { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px 20px;
  margin: 28px 0; padding: 16px 20px; background: var(--soft); border-radius: 12px; }
.match-text { flex: 1 1 200px; }
.match-label { font-weight: 600; font-size: 14px; }
.code { font: 600 26px/1.2 ui-monospace, "SF Mono", Menlo, monospace; letter-spacing: .08em;
  font-variant-numeric: tabular-nums; }
.hint, .note { font-size: 14px; color: var(--muted); }
.match .hint { margin-top: 2px; }
form, #fields { display: grid; gap: 20px; }
form { gap: 24px; }
.field { display: grid; gap: 6px; }
label { font-weight: 600; font-size: 15px; }
.optional { font-weight: 400; color: var(--muted); font-size: 13px; margin-left: 6px; }
.input-row { position: relative; }
input, textarea { display: block; width: 100%; min-width: 0; min-height: 46px; border: 1px solid var(--field);
  border-radius: 10px; padding: 11px 12px; background: var(--surface); color: var(--ink); font: inherit;
  caret-color: var(--accent); transition: border-color .15s, box-shadow .15s; }
input:hover, textarea:hover { border-color: var(--muted); }
input:focus, textarea:focus { outline: 2px solid transparent; outline-offset: 2px; border-color: var(--focus); box-shadow: 0 0 0 4px var(--ring); }
.input-row:has(.toggle) input, .input-row:has(.toggle) textarea { padding-right: 76px;
  font-family: ui-monospace, "SF Mono", Menlo, monospace; }
textarea { min-height: 128px; resize: vertical; }
.concealed { -webkit-text-security: disc; }
button { min-height: 48px; border: 0; border-radius: 10px; padding: 12px 16px; cursor: pointer;
  font: 600 16px/1.5 system-ui, sans-serif; color: var(--on-accent); background: var(--accent);
  transition: background-color .15s; }
button:hover { background: var(--hover); }
button:active { opacity: .85; }
button:disabled { cursor: default; opacity: .65; }
.toggle { position: absolute; top: 7px; right: 7px; min-height: 32px; width: 60px; padding: 4px 0;
  font-size: 13px; border-radius: 7px; background: var(--soft); color: var(--ink); }
.toggle:hover { background: var(--line); }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 3px; }
::selection { background: var(--accent); color: var(--on-accent); }
.actions { display: grid; gap: 12px; }
.note { display: flex; gap: 8px; align-items: flex-start; }
.note svg, .done svg { flex-shrink: 0; }
.note svg { margin-top: 2px; }
#submit { width: 100%; }
#status { color: var(--error); background: var(--error-soft); padding: 10px 14px; border-radius: 10px; font-size: 14px; }
#status:empty { display: none; }
#success { margin-top: 4px; }
.done { display: grid; justify-items: center; text-align: center; gap: 4px; padding: 12px 0 4px; }
.done svg { color: var(--accent); margin-bottom: 8px; }
.done p { color: var(--muted); }
noscript { display: block; margin-top: 16px; color: var(--error); }
[hidden] { display: none !important; }
@media (max-width: 480px) {
  body { padding: 12px; place-items: start center; }
  main { padding: 24px 20px; border-radius: 16px; }
  h1 { font-size: 23px; }
  .match { padding: 14px 16px; }
}
`
