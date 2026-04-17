import { RootProvider } from 'fumadocs-ui/provider';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './global.css';

// Next.js auto-prefixes routes and <Link>s with `basePath`, but it does NOT
// auto-prefix the icon / manifest URLs emitted by the Metadata API — those
// are passed through verbatim as absolute URLs. Derive the same prefix
// `next.config.mjs` uses (from GITHUB_REPOSITORY at build time) so the
// emitted <link rel="icon" ...> tags resolve under /<repo>/ on Pages.
const base =
  process.env.NODE_ENV === 'production' && process.env.GITHUB_REPOSITORY
    ? `/${process.env.GITHUB_REPOSITORY.split('/')[1]}`
    : '';

// The manifest is deliberately NOT listed here — app/manifest.ts owns it
// and Next.js auto-emits the <link rel="manifest"> tag with the right
// basePath prefix. Listing both would produce a duplicate tag.
export const metadata: Metadata = {
  title: {
    default: 'credman docs',
    template: '%s · credman',
  },
  description: 'Per-user credential manager for Linux.',
  icons: {
    icon: [
      { url: `${base}/favicon.ico`, sizes: 'any' },
      { url: `${base}/favicon.svg`, type: 'image/svg+xml' },
      { url: `${base}/favicon-96x96.png`, sizes: '96x96', type: 'image/png' },
    ],
    apple: [{ url: `${base}/apple-touch-icon.png`, sizes: '180x180' }],
  },
};

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
