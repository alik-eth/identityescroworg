// Buffer access for cross-package consumers.
//
// `vite-plugin-node-polyfills` shims the `Buffer` GLOBAL identifier (when
// `globals: { Buffer: true }` is set) — the bundler injects a Buffer
// import + assignment into the prelude wherever it sees a free `Buffer`
// reference. This module exposes `Buffer` as a free identifier so the
// shim hooks correctly, then re-exports it for typed use.
//
// Why we don't just `import { Buffer } from 'buffer'` here: that shim
// rewrites the import path to `vite-plugin-node-polyfills/shims/buffer`,
// which under strict pnpm fails to resolve from @qkb/sdk's compiled JS
// (the plugin is a dep of @qkb/web, not @qkb/sdk).

import type * as BufferNamespace from 'buffer';

// `Buffer` as a free identifier — vite-plugin-node-polyfills' globals
// hook intercepts this at bundle time. In Node test runs, Buffer is a
// built-in global. The `declare` keeps TS happy without an actual import.
declare const Buffer: typeof BufferNamespace.Buffer;

const BufferRef: typeof BufferNamespace.Buffer = Buffer;

export { BufferRef as Buffer };
export type Buffer = BufferNamespace.Buffer;
