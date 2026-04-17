import type { MetadataRoute } from 'next';
import { withBase } from '@/lib/base-path';

// Required under `output: 'export'` — tells Next.js this route handler
// has no request-time state and can be serialised to a static file at
// build. Without it, `next build` errors with:
//   export const dynamic = "force-static"/export const revalidate not configured
export const dynamic = 'force-static';

// PWA manifest for credman's docs. Replaces the static
// public/site.webmanifest so icon URLs can be prefixed with `basePath`
// at build time — see docs/lib/base-path.ts.
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'Credman',
    short_name: 'Credman',
    icons: [
      {
        src: withBase('/web-app-manifest-192x192.png'),
        sizes: '192x192',
        type: 'image/png',
        purpose: 'maskable',
      },
      {
        src: withBase('/web-app-manifest-512x512.png'),
        sizes: '512x512',
        type: 'image/png',
        purpose: 'maskable',
      },
    ],
    theme_color: '#ffffff',
    background_color: '#ffffff',
    display: 'standalone',
  };
}
