// This module is now a thin re-export façade over @zkqes/sdk's errors module.
// Web routes + lib code historically imported from `./errors`; keeping the
// path stable means the migration to the SDK is a one-line dependency add
// rather than a sweeping rewrite.
export {
  ALL_ERROR_CODES,
  BundleError,
  ZkqesError,
  localizeError,
  type ErrorCode,
  type I18nLike,
} from '@zkqes/sdk';
