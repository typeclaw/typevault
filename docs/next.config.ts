import path from 'node:path'

import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  turbopack: {
    root: path.resolve(import.meta.dirname),
  },
  async redirects() {
    return [
      // Temporary, so browsers don't cache it once this site serves real pages.
      { source: '/:path*', destination: 'https://github.com/typeclaw/typevault', permanent: false },
    ]
  },
}

export default nextConfig
