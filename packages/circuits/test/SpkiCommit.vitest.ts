import { describe, expect, it } from 'vitest';

import { parseP256Spki } from '../scripts/spki-commit-ref';

describe('parseP256Spki', () => {
    it('rejects non-91-byte input with descriptive error', () => {
        expect(() => parseP256Spki(Buffer.alloc(90))).toThrow(/expected 91 bytes/i);
        expect(() => parseP256Spki(Buffer.alloc(92))).toThrow(/expected 91 bytes/i);
    });
});
