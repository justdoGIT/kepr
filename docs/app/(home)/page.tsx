import Image from 'next/image';
import Link from 'next/link';
import { withBase } from '@/lib/base-path';

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center text-center p-8">
      <Image
        src={withBase('/logo.png')}
        alt="kepr logo"
        width={128}
        height={128}
        priority
        className="mb-6"
      />
      <h1 className="text-4xl font-bold mb-4">kepr</h1>
      <p className="text-fd-muted-foreground mb-6">
        Per-user credential manager for Linux — unprivileged CLI, root daemon,
        framed JSON over a Unix socket.
      </p>
      <Link
        href="/docs"
        className="text-fd-foreground font-semibold underline underline-offset-4"
      >
        Read the docs →
      </Link>
    </main>
  );
}
