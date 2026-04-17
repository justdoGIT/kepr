import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

// GitHub Pages serves the site under /<repo>, so when we build for
// production we need a matching basePath. Dev server stays at '/' so
// `next dev` works normally.
// The repo name is read from GITHUB_PAGES_REPO (set in the workflow) or
// derived from GITHUB_REPOSITORY ("owner/repo") so forks and renames
// don't require editing this file.
//
// KEEP IN SYNC with the `repoName` derivation in docs/lib/base-path.ts
// (used by the app's Metadata API + <Image> src prefixes). This file
// is .mjs and cannot import the TS helper, so the logic is duplicated
// by hand; update both together when it changes.
const isProd = process.env.NODE_ENV === 'production';
const repoName =
  process.env.GITHUB_PAGES_REPO ||
  process.env.GITHUB_REPOSITORY?.split('/')[1] ||
  '';

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  output: 'export',                                     // static site, emits docs/out
  basePath: isProd && repoName ? `/${repoName}` : '',   // Pages URL: /<repo>
  trailingSlash: true,                       // directory-style URLs on GH Pages
  images: { unoptimized: true },             // Image optimizer needs a server
};

export default withMDX(config);
