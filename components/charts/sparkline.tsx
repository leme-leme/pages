"use client";

// Tiny dependency-free SVG charts. Designed for ~5–60 data points and the
// dashboard's grid (full width, ~80px tall). No tooltips — keep it simple.

type SparklineProps = {
  values: number[];
  height?: number;
  className?: string;
  ariaLabel?: string;
};

export function Sparkline({ values, height = 32, className, ariaLabel }: SparklineProps) {
  if (values.length === 0) {
    return <div className={className} aria-label={ariaLabel} />;
  }
  const width = 100;
  const max = Math.max(1, ...values);
  const min = Math.min(0, ...values);
  const range = max - min || 1;
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values
    .map((v, i) => `${(i * step).toFixed(2)},${(height - ((v - min) / range) * height).toFixed(2)}`)
    .join(" ");

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className={className}
      aria-label={ariaLabel}
      role="img"
      style={{ width: "100%", height }}
    >
      <polyline
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        points={points}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

type BarChartProps = {
  data: { label: string; value: number; sublabel?: string }[];
  height?: number;
  className?: string;
  formatValue?: (n: number) => string;
};

export function BarChart({ data, height = 24, className, formatValue }: BarChartProps) {
  if (data.length === 0) return null;
  const max = Math.max(1, ...data.map((d) => d.value));
  const fmt = formatValue ?? ((n) => n.toLocaleString());

  return (
    <ul className={className}>
      {data.map((row, idx) => (
        <li
          key={`${row.label}-${idx}`}
          className="grid grid-cols-[1fr_3fr_5rem] gap-2 items-center text-sm py-1"
        >
          <div className="truncate font-mono text-xs text-muted-foreground" title={row.label}>
            {row.label}
            {row.sublabel ? <span className="ml-1 text-[10px] opacity-60">{row.sublabel}</span> : null}
          </div>
          <div
            aria-hidden="true"
            className="h-2 bg-muted rounded relative overflow-hidden"
            style={{ height }}
          >
            <div
              className="absolute inset-y-0 left-0 bg-foreground/80"
              style={{ width: `${(row.value / max) * 100}%` }}
            />
          </div>
          <div className="tabular-nums text-right">{fmt(row.value)}</div>
        </li>
      ))}
    </ul>
  );
}

type DayBarsProps = {
  values: { date: string; value: number }[];
  height?: number;
  className?: string;
  formatValue?: (n: number) => string;
};

// Horizontal bar of days, useful for "events per day" / "bytes in per day".
export function DayBars({ values, height = 56, className, formatValue }: DayBarsProps) {
  if (values.length === 0) return null;
  const width = 100;
  const max = Math.max(1, ...values.map((v) => v.value));
  const colWidth = width / values.length;
  const padding = colWidth * 0.15;
  const fmt = formatValue ?? ((n) => n.toLocaleString());
  const total = values.reduce((s, v) => s + v.value, 0);

  return (
    <div className={className}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Bar chart with ${values.length} buckets`}
        style={{ width: "100%", height }}
      >
        {values.map((v, i) => {
          const h = max === 0 ? 0 : (v.value / max) * (height - 2);
          return (
            <rect
              key={v.date}
              x={i * colWidth + padding}
              y={height - h}
              width={colWidth - padding * 2}
              height={h}
              fill="currentColor"
              opacity={0.85}
            >
              <title>{`${v.date}: ${fmt(v.value)}`}</title>
            </rect>
          );
        })}
      </svg>
      <div className="flex justify-between text-[10px] text-muted-foreground mt-1 font-mono tabular-nums">
        <span>{values[0]?.date}</span>
        <span>{fmt(total)}</span>
        <span>{values[values.length - 1]?.date}</span>
      </div>
    </div>
  );
}
