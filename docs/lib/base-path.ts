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
//
// KEEP IN SYNC with the `repoName` derivation in docs/next.config.mjs.
// next.config.mjs is .mjs and cannot import this module, so the logic
// is duplicated by hand; if one changes, update both.

const repoName =
  process.env.GITHUB_PAGES_REPO ||
  process.env.GITHUB_REPOSITORY?.split('/')[1] ||
  '';

export const BASE =
  process.env.NODE_ENV === 'production' && repoName ? `/${repoName}` : '';

export function withBase(path: string): string {
  return `${BASE}${path}`;
}
