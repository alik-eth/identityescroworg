import { renderSigil } from '../lib/sigil';

export interface CertificatePreviewProps {
  tokenId: number;
  nullifier: `0x${string}`;
  chainLabel: string;
  mintTimestamp: number; // unix seconds; for preview, use Math.floor(Date.now()/1000)
}

export function CertificatePreview(props: CertificatePreviewProps) {
  const { tokenId, nullifier, chainLabel, mintTimestamp } = props;
  const sigil = renderSigil(nullifier);
  const issuedDate = new Date(mintTimestamp * 1000).toISOString().slice(0, 10);
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 800 600"
      width="100%"
      role="img"
      aria-label={`Certificate ${tokenId}`}
      style={{ maxWidth: 640, height: 'auto', display: 'block' }}
    >
      <rect width="800" height="600" fill="#F4EFE6" />
      <rect x="12" y="12" width="776" height="576" fill="none" stroke="#1F2D5C" strokeWidth="1.5" />
      <text x="400" y="120" fontFamily="serif" fontSize="44" fontWeight="700" textAnchor="middle" fill="#14130E" letterSpacing="2">
        VERIFIED IDENTITY
      </text>
      <text x="400" y="160" fontFamily="serif" fontSize="22" textAnchor="middle" fill="#14130E" letterSpacing="6">
        ·  UKRAINE  ·
      </text>
      <line x1="120" y1="200" x2="680" y2="200" stroke="#C8BFA8" strokeWidth="1" />
      <text x="400" y="280" fontFamily="serif" fontSize="120" textAnchor="middle" fill="#1F2D5C">
        №{tokenId}
      </text>
      <g dangerouslySetInnerHTML={{ __html: sigil }} />
      <line x1="120" y1="540" x2="680" y2="540" stroke="#C8BFA8" strokeWidth="1" />
      <text x="400" y="565" fontFamily="monospace" fontSize="11" textAnchor="middle" fill="#14130E">
        Issued {issuedDate} · Network {chainLabel}
      </text>
    </svg>
  );
}
