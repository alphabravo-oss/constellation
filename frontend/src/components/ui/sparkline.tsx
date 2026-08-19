/**
 * Tiny dependency-free SVG sparkline.
 * Renders a smoothed polyline + filled gradient area. Designed to sit inside
 * metric tiles next to a big number.
 */
export function Sparkline({
  data,
  width = 96,
  height = 28,
  color = "var(--color-primary)",
  strokeWidth = 1.5,
  filled = true,
}: {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  strokeWidth?: number;
  filled?: boolean;
}) {
  if (!data.length) return null;
  const min = Math.min(...data);
  const max = Math.max(...data, min + 1);
  const dx = data.length > 1 ? width / (data.length - 1) : 0;
  const pts = data.map((v, i) => {
    const x = i * dx;
    const y = height - ((v - min) / (max - min)) * (height - 4) - 2;
    return [x, y] as const;
  });
  const path = pts.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const area = `${path} L ${(pts[pts.length - 1][0]).toFixed(1)} ${height} L 0 ${height} Z`;

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="block" aria-hidden>
      <defs>
        <linearGradient id={`sg-${pts[0][1].toFixed(0)}-${data.length}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor={color} stopOpacity={0.35} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      {filled && <path d={area} fill={`url(#sg-${pts[0][1].toFixed(0)}-${data.length})`} />}
      <path d={path} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
