const SOVEREIGN = '#1F2D5C';
const SEAL = '#8B3A1B';

const COS_TABLE: number[] = [
  1_000_000,  923_879,  707_106,  382_683,
  0,         -382_683, -707_106, -923_879,
  -1_000_000,-923_879, -707_106, -382_683,
  0,          382_683,  707_106,  923_879,
  1_000_000,
];

function cosSinFixed(deg10: number): [number, number] {
  const norm = ((deg10 % 3600) + 3600) % 3600;
  const idx  = Math.floor(norm * 16 / 3600);
  const frac = norm * 16 - idx * 3600;
  const c0 = COS_TABLE[idx]!, c1 = COS_TABLE[idx + 1]!;
  const cosV = Math.trunc(c0 + (c1 - c0) * frac / 3600);
  const sinDeg10 = ((norm + 3600 - 900) % 3600);
  const sIdx  = Math.floor(sinDeg10 * 16 / 3600);
  const sFrac = sinDeg10 * 16 - sIdx * 3600;
  const s0 = COS_TABLE[sIdx]!, s1 = COS_TABLE[sIdx + 1]!;
  const sinV = Math.trunc(s0 + (s1 - s0) * sFrac / 3600);
  return [cosV, sinV];
}

function polygon(sides: number, radius: number, rotation: number): string {
  const pts: string[] = [];
  for (let i = 0; i < sides; i++) {
    const deg10 = Math.floor(i * 3600 / sides) + rotation * 10;
    const [cx, cy] = cosSinFixed(deg10);
    const x = Math.trunc(radius * cx / 1_000_000);
    const y = Math.trunc(radius * cy / 1_000_000);
    pts.push(`${x},${y}`);
  }
  return `<polygon points="${pts.join(' ')} " fill="none" stroke="${SOVEREIGN}" stroke-width="0.9"/>`;
}

export function renderSigil(nullifierHex: string): string {
  // low 16 bytes (last 32 hex chars after `0x`)
  const cleaned = nullifierHex.toLowerCase().replace(/^0x/, '');
  if (cleaned.length !== 64) throw new Error('nullifier must be 32-byte hex');
  const lo = BigInt('0x' + cleaned.slice(32));
  let acc = '';
  for (let i = 0; i < 4; i++) {
    const sidesNibble = Number((lo >> BigInt(i * 4)) & 0x0Fn);
    const rotNibble   = Number((lo >> BigInt(64 + i * 4)) & 0x0Fn);
    const sides    = sidesNibble + 3;
    const radius   = 56 - i * 12;
    const rotation = rotNibble * 22;
    acc += polygon(sides, radius, rotation);
  }
  return (
    `<g transform="translate(400,420)">` +
    `<circle r="64" fill="none" stroke="${SOVEREIGN}" stroke-width="1.2"/>` +
    acc +
    `<path d="M -8 0 L 8 0 M 0 -8 L 0 8" stroke="${SEAL}" stroke-width="2.2"/>` +
    `</g>`
  );
}
