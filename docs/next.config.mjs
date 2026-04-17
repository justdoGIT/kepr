import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

// GitHub Pages serves the site under /<repo>, so when we build for
// production we need a matching basePath. Dev server stays at '/' so
// `next dev` works normally.
const isProd = process.env.NODE_ENV === 'production';

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  output: 'export',                          // static site, emits docs/out
  basePath: isProd ? '/credman' : '',        // Pages URL: /<repo>
  trailingSlash: true,                       // directory-style URLs on GH Pages
  images: { unoptimized: true },             // Image optimizer needs a server
};

export default withMDX(config);
