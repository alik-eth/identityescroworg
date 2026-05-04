// Postinstall shim — runs on every `npm install` that includes
// @zkqes/cli, including workspace dev installs.
//
// Two responsibilities:
//   1. Gate on `dist/src/rapidsnark/postinstall.js` existence — in
//      workspace dev mode, `dist/` may not exist yet (pre-`tsc`),
//      and we don't want a missing-file error to fail the whole
//      install.
//   2. Bridge CJS (this file) → ESM (the compiled postinstall.js
//      is ESM because the package sets `"type": "module"`).  Dynamic
//      `import()` works from CJS; static `require()` of an ESM
//      module would throw ERR_REQUIRE_ESM.
//
// CommonJS to avoid ESM-loader headaches in the npm install context;
// shim is intentionally tiny + boring.

const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const target = path.join(
  __dirname,
  '..',
  'dist',
  'src',
  'rapidsnark',
  'postinstall.js',
);

if (!fs.existsSync(target)) {
  // Workspace dev mode pre-build, or a partial install — silently
  // exit.  T6's postinstall code runs after tsc builds dist/.
  process.exit(0);
}

// Dynamic import to load the ESM module from CJS context.  Errors
// are swallowed: postinstall failures must NOT fail the npm install
// (users on niche platforms still need a working CLI; runtime will
// surface a clear "rapidsnark not found" error if they try
// `zkqes serve` without --rapidsnark-bin).
import(pathToFileURL(target).href)
  .then((mod) => {
    if (typeof mod.runPostinstall === 'function') {
      return mod.runPostinstall();
    }
  })
  .catch((err) => {
    process.stderr.write(
      `[zkqes-cli postinstall] non-fatal: ${err && err.message ? err.message : String(err)}\n`,
    );
    process.exit(0);
  });
