# Agent Guidelines

## Release

Use the **Release** GitHub Actions workflow (`workflow_dispatch`, see `.github/workflows/release.yml`). It validates the version, runs checks, bumps `package.json`, publishes to npm with provenance, then commits, tags, and creates the GitHub release. Tags have no `v` prefix.

The workflow is the only supported release path.

**Version decision.** Specified version → use as-is. Otherwise **default to patch** and only escalate to minor when one of the explicit minor triggers below is clearly met. When in doubt, it's a patch.

**Judge the change, not the commit message.** The bump is decided by what the commits since the last release _actually do_ to the public surface — read the diffs, not the Conventional Commits prefix. A `feat(...)` subject is NOT evidence of a minor bump, and a `fix(...)` subject is NOT proof of a patch. Do not count `feat` commits. For each non-trivial commit, ask: "Does this diff add or break one of the minor triggers below?" If none do, it's a patch no matter how many `feat`s there are. Inspect with `git log <last-tag>..HEAD` plus `git show <sha>` on anything that might touch CLI args, the library exports, or the on-disk vault format.

- **patch** (the default) — bug fixes, refactors, docs, deps, internal-only changes, performance work, test changes, and any user-facing improvement that doesn't add a new public surface or break an existing one. Most releases are patches.
- **minor** — reserve for a genuinely new _public_ surface or a breaking change. Specifically, at least one of: (a) a new CLI subcommand or flag, (b) a new export from the package entry point (`src/index.ts`) or a new field in the vault/grant formats consumers rely on, (c) a backwards-incompatible change to any of the above, including a vault format change that existing vaults can't read. A "new feature" alone is NOT enough — if it doesn't expand or break the public surface in one of those ways, it's a patch.
- Never bump major unless asked. Never ask the user which to bump.

`package.json` is the single source of truth for the version.

**Re-running after partial failure.** Re-run the failed run ("Re-run jobs" in GitHub Actions) rather than dispatching a new one; it reuses whatever already landed (`npm publish` is skipped when the version was published from the same commit, an already-pushed release commit is reused, `gh release` is gated by `gh release view`). Releases are serialized, tags are never moved or force-pushed, and a run whose branch moved since it was dispatched fails before publishing — dispatch a new release from the current tip instead. Dispatching a version whose tag already exists only creates the missing GitHub release.

**Announce the release.** After the workflow completes successfully (`gh release view <version>` returns the tag), post a release note to the **TypeClaw Discord `#releases` channel** via the `agent-discord` skill (`bunx agent-messenger discord`; server `TypeClaw`, channel `releases`). Do this only once the GitHub release actually exists — never pre-announce a release still in flight. Pull the highlights from the generated GitHub release body (`gh release view <version> --json body`), lead with the headline user-facing change, keep it energetic, and include the install line (`bun add -g typevault@<version>`) and the changelog URL. If the announcement fails, the release itself still stands — re-post the note; don't re-run the release workflow.
