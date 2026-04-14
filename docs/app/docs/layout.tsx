import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import Image from 'next/image';
import type { ReactNode } from 'react';
import { source } from '@/lib/source';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      nav={{
        title: (
          <span className="flex items-center gap-2 font-semibold">
            <Image
              src="/logo.png"
              alt=""
              width={24}
              height={24}
              priority
            />
            credman
          </span>
        ),
      }}
      githubUrl="https://github.com/"
    >
      {children}
    </DocsLayout>
  );
}
