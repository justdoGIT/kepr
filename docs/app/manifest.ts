import type { MetadataRoute } from 'next';

// Required under `output: 'export'` — tells Next.js this route handler
// has no request-time state and can be serialised to a static file at
// build. Without it, `next build` errors with:
//   export const dynamic = "force-static"/export const revalidate not configured
export const dynamic = 'force-static';

// PWA manifest for credman's docs. Replaces the static
// public/site.webmanifest so icon URLs can be prefixed with `basePath`
// at build time — see docs/app/layout.tsx for the matching derivation.
const base =
  process.env.NODE_ENV === 'production' && process.env.GITHUB_REPOSITORY
    ? `/${process.env.GITHUB_REPOSITORY.split('/')[1]}`
    : '';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'Credman',
    short_name: 'Credman',
    icons: [
      {
        src: `${base}/web-app-manifest-192x192.png`,
        sizes: '192x192',
        type: 'image/png',
        purpose: 'maskable',
      },
      {
        src: `${base}/web-app-manifest-512x512.png`,
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
