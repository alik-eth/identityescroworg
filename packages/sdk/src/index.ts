// Curated public API for @qkb/sdk.
//
// Modules are extracted incrementally from packages/web/src/lib. Each
// extraction lands as its own commit and exposes its surface here.

export {
  ALL_ERROR_CODES,
  BundleError,
  QkbError,
  localizeError,
  type ErrorCode,
  type I18nLike,
} from './errors/index.js';
