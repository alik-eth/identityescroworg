import { expect } from 'chai';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { hashIncludeChain } from './compile';

const fixtureDir = resolve(__dirname, '..', 'fixtures', 'harness-include-chain');

function seedScratch(): string {
  const scratch = mkdtempSync(join(tmpdir(), 'circom-harness-'));
  for (const name of ['main.circom', 'helper.circom', 'primitive.circom']) {
    copyFileSync(join(fixtureDir, name), join(scratch, name));
  }
  return scratch;
}

describe('hashIncludeChain', () => {
  it('changes when a directly-included helper is modified (depth 1)', () => {
    const scratch = seedScratch();
    try {
      const rootPath = join(scratch, 'main.circom');
      const before = hashIncludeChain(rootPath, []);

      const helperPath = join(scratch, 'helper.circom');
      const mutated = `${readFileSync(helperPath, 'utf8')}\n// cache-bust\n`;
      writeFileSync(helperPath, mutated);

      const after = hashIncludeChain(rootPath, []);
      expect(after).to.not.equal(
        before,
        'modifying a directly-included file must invalidate the cache key',
      );
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('is stable across two runs over an unchanged file tree', () => {
    const scratch = seedScratch();
    try {
      const rootPath = join(scratch, 'main.circom');
      const first = hashIncludeChain(rootPath, []);
      const second = hashIncludeChain(rootPath, []);
      expect(second).to.equal(
        first,
        'unchanged sources must yield a stable cache key (cache HIT)',
      );
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('changes when a transitively-included file is modified (depth 2)', () => {
    const scratch = seedScratch();
    try {
      const rootPath = join(scratch, 'main.circom');
      const before = hashIncludeChain(rootPath, []);

      // main.circom -> helper.circom -> primitive.circom (depth 2)
      const primitivePath = join(scratch, 'primitive.circom');
      const mutated = `${readFileSync(primitivePath, 'utf8')}\n// depth-2 cache-bust\n`;
      writeFileSync(primitivePath, mutated);

      const after = hashIncludeChain(rootPath, []);
      expect(after).to.not.equal(
        before,
        'modifying a depth-2 transitive include must invalidate the cache key',
      );
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('throws loudly on a missing include (no silent skip)', () => {
    const scratch = mkdtempSync(join(tmpdir(), 'circom-harness-'));
    try {
      const rootPath = join(scratch, 'broken.circom');
      writeFileSync(
        rootPath,
        'pragma circom 2.1.6;\ninclude "./does-not-exist.circom";\n',
      );
      expect(() => hashIncludeChain(rootPath, [])).to.throw(/include not found/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('terminates on a circular include (a -> b -> a)', () => {
    const scratch = mkdtempSync(join(tmpdir(), 'circom-harness-'));
    try {
      const aPath = join(scratch, 'a.circom');
      const bPath = join(scratch, 'b.circom');
      writeFileSync(aPath, 'pragma circom 2.1.6;\ninclude "./b.circom";\n');
      writeFileSync(bPath, 'pragma circom 2.1.6;\ninclude "./a.circom";\n');
      // No assertion on the value — just that it returns instead of looping.
      const h = hashIncludeChain(aPath, []);
      expect(h).to.match(/^[0-9a-f]{64}$/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('resolves includes via lib paths (circomlib-style)', () => {
    const scratch = mkdtempSync(join(tmpdir(), 'circom-harness-'));
    const lib = mkdtempSync(join(tmpdir(), 'circom-harness-lib-'));
    try {
      const libSub = join(lib, 'fakelib');
      require('node:fs').mkdirSync(libSub, { recursive: true });
      const libHelper = join(libSub, 'helper.circom');
      writeFileSync(libHelper, 'pragma circom 2.1.6;\n// lib helper\n');

      const rootPath = join(scratch, 'root.circom');
      writeFileSync(
        rootPath,
        'pragma circom 2.1.6;\ninclude "fakelib/helper.circom";\n',
      );

      const before = hashIncludeChain(rootPath, [lib]);
      writeFileSync(libHelper, 'pragma circom 2.1.6;\n// lib helper v2\n');
      const after = hashIncludeChain(rootPath, [lib]);
      expect(after).to.not.equal(
        before,
        'modifying a lib-resolved include must invalidate the cache key',
      );
    } finally {
      rmSync(scratch, { recursive: true, force: true });
      rmSync(lib, { recursive: true, force: true });
    }
  });

  it('ignores include lines inside block and line comments', () => {
    const scratch = mkdtempSync(join(tmpdir(), 'circom-harness-'));
    try {
      const rootPath = join(scratch, 'root.circom');
      writeFileSync(
        rootPath,
        [
          'pragma circom 2.1.6;',
          '// include "./not-really.circom";',
          '/* include "./also-not.circom"; */',
          '',
        ].join('\n'),
      );
      // Should not throw despite the two missing-looking includes — both are
      // commented out and must be skipped by the parser.
      const h = hashIncludeChain(rootPath, []);
      expect(h).to.match(/^[0-9a-f]{64}$/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});
