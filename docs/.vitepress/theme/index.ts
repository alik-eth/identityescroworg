// docs.zkqes.org — civic-monumental theme override.
//
// Extends VitePress's default theme with custom CSS that lifts the
// civic-monumental aesthetic from `packages/web/src/styles.css`
// (color tokens + type stack + paper grain) so the doc site reads
// as a sibling surface to zkqes.org root and app.zkqes.org.
//
// We extend the default theme rather than build from scratch
// because:
//   - The default theme has solid dark-mode toggle + client-side
//     local search + responsive sidebar logic we don't want to
//     reimplement.
//   - The default theme uses CSS variables (`--vp-c-*`,
//     `--vp-font-family-*`) for all visual tokens, so the override
//     is a small CSS file rather than a fork.
//
// Source-of-truth: `packages/web/src/styles.css` is the canonical
// civic-monumental palette + type stack. The doc-site `custom.css`
// duplicates the tokens (with VitePress-flavored property names);
// when the SPA's tokens drift, the doc-site CSS needs a manual
// re-sync. Sync is checked by visual inspection at deploy time —
// no automated test (cross-package CSS-token diffing is over-
// engineering for V1).
import DefaultTheme from 'vitepress/theme';
import type { Theme } from 'vitepress';
import './custom.css';

export default {
  extends: DefaultTheme,
} satisfies Theme;
