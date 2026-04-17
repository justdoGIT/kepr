// Derive the production basePath from the build-time GitHub env so
// Metadata API icon URLs, PWA manifest icon srcs, and <Image> / <img>
// src attributes resolve correctly under /<repo>/ on GitHub Pages.
//
// Next.js auto-prefixes the router and <Link>; Metadata API fields and
// <Image src> under `images: { unoptimized: true }` (the static-export
// default) do NOT get auto-prefixed, so every such reference uses
// `withBase(...)` to stay aligned with next.config.mjs.
//
// In dev (NODE_ENV !== 'production') or outside CI this is an empty
// string, so `next dev` keeps serving assets from root.

export const BASE =
  process.env.NODE_ENV === 'production' && process.env.GITHUB_REPOSITORY
    ? `/${process.env.GITHUB_REPOSITORY.split('/')[1]}`
    : '';

export function withBase(path: string): string {
  return `${BASE}${path}`;
}
