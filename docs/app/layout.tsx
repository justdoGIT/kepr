import { RootProvider } from 'fumadocs-ui/provider';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { withBase } from '@/lib/base-path';
import './global.css';

// Next.js auto-prefixes routes and <Link>s with `basePath`, but it does NOT
// auto-prefix the icon URLs emitted by the Metadata API — those are passed
// through verbatim. See docs/lib/base-path.ts.
//
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
      { url: withBase('/favicon.ico'), sizes: 'any' },
      { url: withBase('/favicon.svg'), type: 'image/svg+xml' },
      { url: withBase('/favicon-96x96.png'), sizes: '96x96', type: 'image/png' },
    ],
    apple: [{ url: withBase('/apple-touch-icon.png'), sizes: '180x180' }],
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
