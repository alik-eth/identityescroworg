// docs.zkqes.org — VitePress site config.
//
// Per BRAND.md §Domains (locked 2026-05-03), docs.zkqes.org renders
// the `docs/` markdown tree as a static site for developers,
// integrators, and researchers. Sister surfaces:
//   - zkqes.org root  → pre-ceremony hero (#60, separate worktree)
//   - app.zkqes.org   → register flow (post-§9.4, separate deploy)
//
// **Source-of-truth contract:** the `docs/` markdown is the canonical
// source; this config is just nav + theme + URL polish on top. We do
// NOT rewrite spec content into VitePress conventions — if a contributor
// edits a spec at `docs/superpowers/specs/2026-04-29-v5-architecture-design.md`,
// the doc site picks it up unchanged.
//
// **Inclusion policy** (per BRAND.md §"How to write about the project"):
//   - Deleted Phase-2 docs — `docs/qie/` excluded (deleted in v0.6.0 rename).
//   - Marketing drafts are not public docs surface — `docs/marketing/` excluded.
//   - Worker-handoff sessions are scaffolding — `docs/handoffs/` excluded.
//   - Working notes — `docs/superpowers/notes/` excluded.
//   - Deferred specs (trustless-eIDAS, historical-phase2) are excluded by default.
//     Inclusion of a parked spec needs lead sign-off.
//
// **URL policy:** dated filenames in the source tree
// (`2026-04-29-v5-architecture-design.md`) get rewrites to clean URLs
// (`/specs/v5-architecture`). Source paths stay dated for chronology;
// public URLs surface the topic.
import { defineConfig } from 'vitepress';

export default defineConfig({
  title: 'zk-QES docs',
  // Per BRAND.md §"How to write about the project": single noun is zkqes.
  description:
    'A zero-knowledge protocol over qualified electronic signatures. ' +
    'Documentation for zkqes — the V1 implementation.',

  // Match the SPA's `<meta>` aesthetic; docs.zkqes.org carries a
  // sibling civic-monumental theme override (see `theme/index.ts`).
  cleanUrls: true,
  lastUpdated: true,

  // Google Fonts for the civic-monumental type stack — same fonts
  // the SPA loads. EB Garamond (display headings + fine), Inter Tight
  // (body), JetBrains Mono (code). Preconnect first for handshake
  // savings; stylesheet second.
  head: [
    [
      'link',
      { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
    ],
    [
      'link',
      {
        rel: 'preconnect',
        href: 'https://fonts.gstatic.com',
        crossorigin: '',
      },
    ],
    [
      'link',
      {
        rel: 'stylesheet',
        href:
          'https://fonts.googleapis.com/css2' +
          '?family=EB+Garamond:ital,wght@0,400;0,600;0,700;1,400' +
          '&family=Inter+Tight:wght@400;500;600' +
          '&family=JetBrains+Mono:wght@400;500' +
          '&display=swap',
      },
    ],
  ],

  // The repo root has a single `docs/` folder; VitePress is rooted
  // there (see `docs:build` script in root package.json:
  // `vitepress build docs`).
  //
  // Files we DON'T want rendered in the public site, even though they
  // live under `docs/` for orchestration purposes:
  srcExclude: [
    // zkqes Phase-2 QIE docs (deleted in v0.6.0 rename); glob retained as safety net.
    'qie/**',
    // Marketing drafts — not part of the developer doc surface.
    'marketing/**',
    // Worker-session handoffs — internal scaffolding.
    'handoffs/**',
    // Working notes — pre-spec scratch.
    'superpowers/notes/**',
    // Specs that are parked or historical-only — explicit list rather
    // than glob so a future addition shows up in this file's diff.
    'superpowers/specs/2026-04-17-qie-mvp-refinement.md',
    'superpowers/specs/2026-04-17-qie-phase2-design.md',
    'superpowers/specs/2026-04-17-qkb-phase1-design.md',
    'superpowers/specs/2026-04-23-qkb-binding-v2-policy-root.md',
    'superpowers/specs/2026-04-24-per-country-registries-design.md',
    'superpowers/specs/2026-04-27-trustless-eidas.md',
    'superpowers/specs/2026-04-27-prod-frontend.md',
    'superpowers/specs/2026-04-30-issuer-blind-nullifier-contract-review.md',
    'superpowers/specs/2026-05-01-keccak-on-chain-contract-review.md',
    // Specs that need markdown normalization before VitePress can
    // render them — bare `<word>` placeholders, ASCII-art outside
    // code fences, etc. Vue's template parser interprets the angle
    // brackets as HTML tags and the build aborts. Listed here as a
    // punch-list for a content-normalization commit; the underlying
    // spec content is sound, only the markdown framing needs to be
    // VitePress-friendly. Lead's directive ("don't rewrite spec
    // content") preserved — the fix is wrapping in code fences /
    // backslash-escaping angle brackets, which is markdown-syntax
    // normalization rather than semantic editing.
    'superpowers/specs/2026-05-03-qkb-helper-design.md',
    // Worker plans — kept on contributing surface but not exhaustive
    // index. C3 will curate the whitelist via `rewrites` + sidebar.
    'superpowers/plans/2026-04-17-qie-*.md',
    'superpowers/plans/2026-04-17-qkb-*.md',
    'evaluations/**',
    'cli-release-homebrew/**',
  ],

  // Map dated source paths to clean public URLs. Source filename
  // chronology preserved; URLs surface the topic. The plan-to-URL map
  // is the source-of-truth for "what does docs.zkqes.org actually
  // surface" — adding a route requires adding a mapping here.
  rewrites: {
    'superpowers/specs/2026-04-19-qkb-cli-design.md':
      'specs/zkqes-cli-design.md',
    'superpowers/specs/2026-04-29-v5-architecture-design.md':
      'specs/v5-architecture.md',
    'superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md':
      'specs/v5_1-wallet-bound-nullifier.md',
    'superpowers/specs/2026-05-01-keccak-on-chain-amendment.md':
      'specs/v5_2-keccak-on-chain.md',
    'superpowers/specs/2026-05-03-v5_3-oid-anchor-amendment.md':
      'specs/v5_3-oid-anchor.md',
    'superpowers/specs/2026-04-18-person-nullifier-amendment.md':
      'specs/person-nullifier.md',
    'superpowers/specs/2026-04-18-split-proof-pivot.md':
      'specs/split-proof-pivot.md',
    // Orchestration plans surfaced in the Contributing section.
    'superpowers/plans/2026-04-29-v5-architecture-orchestration.md':
      'contributing/plans/v5-architecture.md',
    'superpowers/plans/2026-04-30-wallet-bound-nullifier-orchestration.md':
      'contributing/plans/v5_1-wallet-bound-nullifier.md',
    'superpowers/plans/2026-05-03-qkb-cli-server-orchestration.md':
      'contributing/plans/v5_4-zkqes-cli-server.md',
    'superpowers/plans/2026-05-03-v5_3-orchestration.md':
      'contributing/plans/v5_3-orchestration.md',
    'cli-release.md': 'install/zkqes-cli.md',
    'integrations.md': 'reference/integrations.md',
    'release-notes/v0.5.2-contracts.md':
      'reference/release-notes/v0.5.2-contracts.md',
    'ceremony/README.md': 'ceremony/index.md',
  },

  themeConfig: {
    siteTitle: 'zk-QES',
    nav: [
      { text: 'Install', link: '/install/zkqes-cli' },
      { text: 'Specs', link: '/specs/v5-architecture' },
      { text: 'Ceremony', link: '/ceremony/' },
      { text: 'Reference', link: '/reference/integrations' },
      { text: 'Brand', link: '/brand' },
      { text: 'Contributing', link: '/contributing/' },
      // Cross-link to the project landing — same brand, different
      // surface.
      { text: 'zkqes.org →', link: 'https://zkqes.org' },
    ],

    sidebar: {
      // C3 will wire up complete sidebars for every section. For C1
      // (this scoping commit), each section renders with VitePress's
      // default auto-sidebar behaviour from the markdown frontmatter
      // — the navigation is functional but not yet curated.
      '/specs/': [
        {
          text: 'Specs',
          items: [
            { text: 'V5 architecture', link: '/specs/v5-architecture' },
            {
              text: 'V5.1 — wallet-bound nullifier',
              link: '/specs/v5_1-wallet-bound-nullifier',
            },
            {
              text: 'V5.2 — keccak-on-chain',
              link: '/specs/v5_2-keccak-on-chain',
            },
            { text: 'V5.3 — OID anchor', link: '/specs/v5_3-oid-anchor' },
            { text: 'zkqes CLI design', link: '/specs/zkqes-cli-design' },
          ],
        },
        {
          text: 'Historical (pre-V5)',
          collapsed: true,
          items: [
            { text: 'Person nullifier amendment', link: '/specs/person-nullifier' },
            { text: 'Split-proof pivot', link: '/specs/split-proof-pivot' },
          ],
        },
      ],
      '/install/': [
        {
          text: 'Install',
          items: [{ text: 'zkqes CLI', link: '/install/zkqes-cli' }],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Integrations', link: '/reference/integrations' },
            {
              text: 'Release notes',
              collapsed: false,
              items: [
                {
                  text: 'v0.5.2 contracts',
                  link: '/reference/release-notes/v0.5.2-contracts',
                },
              ],
            },
          ],
        },
      ],
      '/ceremony/': [
        {
          text: 'Ceremony',
          items: [{ text: 'Overview', link: '/ceremony/' }],
        },
      ],
      '/contributing/': [
        {
          text: 'Contributing',
          items: [{ text: 'Overview', link: '/contributing/' }],
        },
        {
          text: 'Orchestration plans',
          items: [
            {
              text: 'V5 architecture',
              link: '/contributing/plans/v5-architecture',
            },
            {
              text: 'V5.1 — wallet-bound nullifier',
              link: '/contributing/plans/v5_1-wallet-bound-nullifier',
            },
            {
              text: 'V5.3 — OID anchor',
              link: '/contributing/plans/v5_3-orchestration',
            },
            {
              text: 'V5.4 — zkqes CLI server',
              link: '/contributing/plans/v5_4-zkqes-cli-server',
            },
          ],
        },
      ],
    },

    socialLinks: [
      {
        icon: 'github',
        link: 'https://github.com/alik-eth/zkqes',
      },
    ],

    editLink: {
      pattern:
        'https://github.com/alik-eth/zkqes/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    footer: {
      message:
        'Released under the MIT License. zk-QES — a zero-knowledge protocol over qualified electronic signatures.',
      copyright: 'Copyright © 2026 — zkqes contributors',
    },

    search: {
      provider: 'local',
    },
  },

  // Markdown config — enable the include directive so we can pull
  // BRAND.md from the repo root into `docs/brand.md` without
  // duplicating content.
  markdown: {
    // Default; just being explicit so a future contributor sees the
    // include directive is active. `<!--@include: ../BRAND.md-->`
    // dynamically pulls the source file at build time.
    config: () => {
      // No-op; VitePress's default markdown-it config already
      // includes the markdownItIncludeFile plugin via the framework.
    },
    // Alias `circom` to a similar grammar so shiki stops falling back
    // to plaintext on V5 circuit code blocks. Circom's syntax is
    // closer to Rust (pragma, template, signal) than TypeScript;
    // pragma + template highlight reasonably under the rust grammar.
    // Not perfect but eliminates the 11 build-time warnings without
    // needing a full custom textmate grammar (overkill for V1).
    languageAlias: {
      circom: 'rust',
    },
  },

  // Ignore broken internal links from the dead-code branch test
  // until C3 finishes wiring all sections. C3 will flip this to a
  // strict check.
  ignoreDeadLinks: true,
});
