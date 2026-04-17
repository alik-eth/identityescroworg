import { describe, it, expect } from 'vitest';
import {
  buildNotaryAttest,
  parseNotaryAttest,
  NOTARY_ATTEST_DOMAIN,
} from '../../src/lib/notary-attest';

describe('notary-attest', () => {
  it('emits alphabetically-sorted JCS with the frozen domain', () => {
    const bytes = buildNotaryAttest({
      recipient_pk: '0x01',
      escrowId: '0xabc',
    });
    expect(new TextDecoder().decode(bytes)).toBe(
      '{"domain":"qie-notary-recover/v1","escrowId":"0xabc","recipient_pk":"0x01"}',
    );
  });

  it('is byte-stable regardless of input property order', () => {
    const a = buildNotaryAttest({ recipient_pk: '0x01', escrowId: '0xabc' });
    const b = buildNotaryAttest({ escrowId: '0xabc', recipient_pk: '0x01' });
    expect(new TextDecoder().decode(a)).toBe(new TextDecoder().decode(b));
  });

  it('round-trips via parseNotaryAttest', () => {
    const payload = { recipient_pk: '0x01', escrowId: '0xabc' } as const;
    const bytes = buildNotaryAttest(payload);
    const back = parseNotaryAttest(bytes);
    expect(back.domain).toBe(NOTARY_ATTEST_DOMAIN);
    expect(back.recipient_pk).toBe('0x01');
    expect(back.escrowId).toBe('0xabc');
  });

  it('rejects parse with wrong domain', () => {
    const bytes = new TextEncoder().encode(
      '{"domain":"other/v1","escrowId":"0x0","recipient_pk":"0x0"}',
    );
    expect(() => parseNotaryAttest(bytes)).toThrow(/unexpected domain/);
  });
});
