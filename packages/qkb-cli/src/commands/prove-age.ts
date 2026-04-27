/**
 * `qkb prove-age` — re-export from `../prove-age.ts` so the dispatcher can
 * `import { runProveAge } from './commands/prove-age.js'` without the body
 * needing to move yet.
 */
export { runProveAge, type ProveAgeOptions } from '../prove-age.js';
