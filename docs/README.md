# TypeVault site

A Next.js app that redirects every path to the [GitHub repository](https://github.com/typeclaw/typevault). The redirect lives in `next.config.ts`.

The Markdown guides and `diagrams/` beside it are the repository's documentation, linked from the root README. The app doesn't serve them.

## Development

```sh
bun install
bun run dev
```

## Deploy

Create a Vercel project with `docs` as its root directory.
