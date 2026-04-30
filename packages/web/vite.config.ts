import { createRequire } from 'node:module';
import { dirname } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

// vite-plugin-node-polyfills rewrites `import 'buffer'` (and the `Buffer`
// global hook) to `import 'vite-plugin-node-polyfills/shims/buffer'`. With
// strict pnpm, that subpath only resolves from packages that directly
// depend on the plugin — @qkb/web does, but @qkb/sdk's compiled JS
// doesn't. Provide an explicit alias so the rewritten import resolves
// from any context.
// Locate the polyfill plugin's `shims/buffer` package by anchoring on
// the plugin entry-point and walking up to the package root.
const require = createRequire(import.meta.url);
const polyfillEntry = require.resolve('vite-plugin-node-polyfills');
// .../vite-plugin-node-polyfills/dist/index.js → walk to package root.
const polyfillRoot = dirname(dirname(polyfillEntry));
const bufferShimDir = `${polyfillRoot}/shims/buffer`;

export default defineConfig({
  base: process.env.VITE_BASE ?? '/',
  resolve: {
    alias: {
      'vite-plugin-node-polyfills/shims/buffer': bufferShimDir,
    },
  },
  plugins: [
    react(),
    tailwindcss(),
    nodePolyfills({ include: ['buffer'], globals: { Buffer: true } }),
  ],
  build: {
    target: 'es2022',
  },
  optimizeDeps: {
    exclude: ['snarkjs'],
  },
  worker: {
    format: 'es',
  },
});
