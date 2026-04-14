import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col justify-center text-center p-8">
      <h1 className="text-4xl font-bold mb-4">credman</h1>
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
