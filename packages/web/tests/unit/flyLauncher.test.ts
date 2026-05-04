// Vitest unit tests for the Fly launcher helpers (task A2.7b).
import { describe, expect, it } from 'vitest';
import {
  ENTROPY_HEX_LEN,
  buildFlyLaunchCommand,
  generateEntropyHex,
  isValidEntropyHex,
  parseRoundFromUrl,
  slugify,
} from '../../src/lib/flyLauncher';

describe('slugify', () => {
  it('lowercases ASCII handles', () => {
    expect(slugify('Alice')).toBe('alice');
  });
  it('collapses whitespace and punctuation into a single hyphen', () => {
    expect(slugify("Alice O'Neill")).toBe('alice-o-neill');
    expect(slugify('vitalik   buterin')).toBe('vitalik-buterin');
    expect(slugify('  test  ')).toBe('test');
  });
  it('drops Cyrillic / Unicode entirely (Fly app names are ASCII-only)', () => {
    // The lead's spec scopes app-name to a-z0-9-; non-ASCII collapses
    // to hyphens which then get stripped from the edges.
    expect(slugify('Олександр')).toBe('');
    expect(slugify('Alik 🔐')).toBe('alik');
  });
  it('truncates to 30 characters', () => {
    const long = 'a'.repeat(60);
    expect(slugify(long)).toHaveLength(30);
  });
  it('strips leading and trailing hyphens', () => {
    expect(slugify('---hello---')).toBe('hello');
    expect(slugify('!!!a!!!')).toBe('a');
  });
});

describe('isValidEntropyHex', () => {
  it('accepts exactly 64 lowercase hex characters', () => {
    expect(isValidEntropyHex('a'.repeat(64))).toBe(true);
    expect(isValidEntropyHex('cafebabe'.repeat(8))).toBe(true);
  });
  it('rejects uppercase hex (Fly secrets are case-sensitive; we normalise on input)', () => {
    expect(isValidEntropyHex('A'.repeat(64))).toBe(false);
  });
  it('rejects wrong length', () => {
    expect(isValidEntropyHex('a'.repeat(63))).toBe(false);
    expect(isValidEntropyHex('a'.repeat(65))).toBe(false);
    expect(isValidEntropyHex('')).toBe(false);
  });
  it('rejects non-hex characters', () => {
    expect(isValidEntropyHex('z'.repeat(64))).toBe(false);
    expect(isValidEntropyHex('0x' + 'a'.repeat(62))).toBe(false);
    expect(isValidEntropyHex('a'.repeat(63) + ' ')).toBe(false);
  });
});

describe('generateEntropyHex', () => {
  it('returns 64 lowercase hex characters', () => {
    const hex = generateEntropyHex();
    expect(hex).toHaveLength(ENTROPY_HEX_LEN);
    expect(isValidEntropyHex(hex)).toBe(true);
  });
  it('does not return the same value twice in a row (sanity-check the RNG)', () => {
    // crypto.getRandomValues collision over 256 bits has probability
    // ~2^-256; if this ever fails the test infra is the bug.
    const a = generateEntropyHex();
    const b = generateEntropyHex();
    expect(a).not.toBe(b);
  });
});

describe('parseRoundFromUrl', () => {
  it('extracts the round from a /rounds/round-N.zkey path', () => {
    expect(
      parseRoundFromUrl(
        'https://prove.zkqes.org/ceremony/rounds/round-3.zkey?sig=abc',
      ),
    ).toBe(3);
    expect(
      parseRoundFromUrl('https://example.com/path/round-12.zkey'),
    ).toBe(12);
  });
  it('matches case-insensitively', () => {
    expect(parseRoundFromUrl('https://example.com/Round-4.zkey')).toBe(4);
  });
  it('returns null when no round segment is present', () => {
    expect(parseRoundFromUrl('https://example.com/upload')).toBeNull();
    expect(parseRoundFromUrl('')).toBeNull();
  });
  it('returns null on a non-positive round number', () => {
    // Defensive — the regex requires \d+ so this can't actually
    // produce a 0, but the code path is exercised for safety.
    expect(parseRoundFromUrl('https://example.com/round-0.zkey')).toBeNull();
  });
});

describe('buildFlyLaunchCommand', () => {
  const baseInputs = {
    name: 'alice',
    round: 3,
    signedPutUrl: 'https://prove.zkqes.org/upload?sig=abc&exp=1234',
    entropyHex: 'cafebabe'.repeat(8),
  };

  it('renders the full canonical six-step sequence verbatim', () => {
    const cmd = buildFlyLaunchCommand(baseInputs);
    // The exact lead-specified sequence — line by line, no extras.
    expect(cmd).toContain('APP="zkqes-ceremony-alice"');
    expect(cmd).toContain('flyctl apps create "$APP" --org personal');
    expect(cmd).toContain('flyctl secrets set \\');
    expect(cmd).toContain('  ROUND="3" \\');
    expect(cmd).toContain(
      '  PREV_ROUND_URL="https://prove.zkqes.org/ceremony/rounds/round-2.zkey" \\',
    );
    expect(cmd).toContain(
      '  R1CS_URL="https://prove.zkqes.org/ceremony/main.r1cs" \\',
    );
    expect(cmd).toContain(
      '  PTAU_URL="https://prove.zkqes.org/ceremony/pot/pot22.ptau" \\',
    );
    expect(cmd).toContain(
      `  SIGNED_PUT_URL='${baseInputs.signedPutUrl}' \\`,
    );
    expect(cmd).toContain(`  CONTRIBUTOR_NAME='alice' \\`);
    expect(cmd).toContain(
      `  CONTRIBUTOR_ENTROPY=${baseInputs.entropyHex} \\`,
    );
    expect(cmd).toContain('  -a "$APP"');
    expect(cmd).toContain(
      '  --image ghcr.io/zkqes/zkqes-ceremony:v1 \\',
    );
    expect(cmd).toContain('  --vm-size performance-cpu-4x \\');
    expect(cmd).toContain('  --vm-memory 32768 \\');
    expect(cmd).toContain('  --strategy immediate \\');
    expect(cmd).toContain('flyctl logs -a "$APP" --follow');
    expect(cmd).toContain(
      "# After the run completes (you'll see SHA-256 in the logs), save it, then:",
    );
    expect(cmd).toContain('flyctl apps destroy "$APP" --yes');
  });

  it('uses the slugified name in $APP but preserves the original in CONTRIBUTOR_NAME', () => {
    const cmd = buildFlyLaunchCommand({
      ...baseInputs,
      name: "Alice O'Neill",
    });
    expect(cmd).toContain('APP="zkqes-ceremony-alice-o-neill"');
    expect(cmd).toContain(`CONTRIBUTOR_NAME='Alice O'Neill'`);
  });

  it('derives PREV_ROUND_URL from the input round (round-1 zkey)', () => {
    const cmd = buildFlyLaunchCommand({ ...baseInputs, round: 7 });
    expect(cmd).toContain(
      'PREV_ROUND_URL="https://prove.zkqes.org/ceremony/rounds/round-6.zkey"',
    );
    expect(cmd).toContain('ROUND="7"');
  });

  it('keeps CONTRIBUTOR_ENTROPY unquoted (pure hex, no shell metachars)', () => {
    const cmd = buildFlyLaunchCommand(baseInputs);
    // Single-quoted entropy would be a regression — the cookbook
    // specifies unquoted hex so the secret is set without an extra
    // pair of quote characters in the value.
    expect(cmd).not.toContain(`CONTRIBUTOR_ENTROPY='${baseInputs.entropyHex}'`);
    expect(cmd).toContain(`CONTRIBUTOR_ENTROPY=${baseInputs.entropyHex} \\`);
  });
});
