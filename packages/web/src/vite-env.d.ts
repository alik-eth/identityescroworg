/// <reference types="vite/client" />

// Typed env vars consumed by `@zkqes/web`. Vite injects these into
// `import.meta.env` at build time; declaring the shape here gives
// autocomplete + type-checking at every call site.
//
// Keep alphabetized by var name. Document the consumer + default in
// the JSDoc above each field so a future contributor can decide whether
// to set the var or leave it default without grepping the codebase.
interface ImportMetaEnv {
  /** Production status feed URL for the ceremony page. Default: same-
   *  origin `/ceremony/status.json`. Set to an absolute URL (e.g.
   *  `https://prove.zkqes.org/ceremony/status.json` or, post-
   *  DNS migration, `https://prove.zkqes.org/ceremony/status.json`)
   *  when the SPA is served from a different origin than the status
   *  feed. Consumed by `lib/ceremonyStatus.ts`. */
  readonly VITE_CEREMONY_STATUS_URL?: string;
  /** Wallet chain selector. `sepolia` enables wagmi's testing config;
   *  any other value falls through to mainnet. Consumed by `lib/wagmi.ts`. */
  readonly VITE_CHAIN?: string;
  /** When set to `'1'`, swaps the snarkjs prover for a deterministic
   *  mock. Used by Playwright e2e to keep tests fast. Consumed by
   *  `lib/uaProofPipelineV5{,_2}.ts` + the V5 flow components. */
  readonly VITE_USE_MOCK_PROVER?: string;
  /** WalletConnect project id. Required for production builds with
   *  WalletConnect enabled; e2e uses a mock id. Consumed by `lib/wagmi.ts`. */
  readonly VITE_WALLETCONNECT_PROJECT_ID?: string;
  /** GH Pages base path (e.g. `/`). Read in
   *  `vite.config.ts`; not consumed at runtime. */
  readonly VITE_BASE?: string;
  /** SPA build target — 'landing' for zkqes.org root (hero + ceremony
   *  pages only), 'app' for app.zkqes.org (full register + rotate
   *  flow). Consumed by `lib/buildTarget.ts`; defaults to 'app' for
   *  backwards-compat with the existing pages.yml workflow. */
  readonly VITE_TARGET?: 'landing' | 'app';
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
