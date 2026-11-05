import { z } from 'zod'

/**
 * This release's version, read once when the module loads: a daemon reports it, so a CLI from another release knows
 * not to talk to it. Read any later, an idle daemon would report the version of a package upgraded under it.
 */
export const PACKAGE_VERSION = z
  .object({ version: z.string() })
  .parse(await Bun.file(new URL('../../package.json', import.meta.url)).json()).version
