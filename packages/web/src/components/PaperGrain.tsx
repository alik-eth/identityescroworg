// Decorative SVG noise overlay; layered absolutely above page background
// to add subtle paper grain. The actual base noise is in styles.css; this
// component allows route-local intensity overrides.
export function PaperGrain({ opacity = 0.04 }: { opacity?: number }) {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0"
      style={{
        opacity,
        backgroundImage: `url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='1.4' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 0.078  0 0 0 0 0.075  0 0 0 0 0.054  0 0 0 0.4 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>")`,
        backgroundRepeat: 'repeat',
      }}
    />
  );
}
