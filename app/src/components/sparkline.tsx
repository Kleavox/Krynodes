import { Fragment, useState, type PointerEvent } from "react";

import { clockTime } from "@/lib/format";
import { sparklineArea, sparklineSegments } from "@/lib/series";
import { cn } from "@/lib/utils";

const percent = (value: number) => `${Math.round(value)}%`;

export function Sparkline({
  values,
  times,
  max = 100,
  label,
  format = percent,
  className,
}: {
  values: (number | null)[];
  times?: number[];
  max?: number;
  label: string;
  format?: (value: number) => string;
  className?: string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const segments = sparklineSegments(values, max);
  const count = values.length;
  const top = max > 0 ? max : 1;
  const pick = (event: PointerEvent<HTMLDivElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    if (!times || box.width === 0 || count === 0) return;
    const fraction = Math.min(
      Math.max((event.clientX - box.left) / box.width, 0),
      1,
    );
    setHover(Math.round(fraction * (count - 1)));
  };
  const value = hover === null ? null : (values[hover] ?? null);
  const time = hover === null ? undefined : times?.[hover];
  const x = hover === null || count < 2 ? 50 : (hover / (count - 1)) * 100;
  const y =
    value === null ? null : (1 - Math.min(Math.max(value, 0), top) / top) * 100;
  return (
    <div
      className={cn("relative h-8 w-full", className)}
      onPointerMove={pick}
      onPointerDown={pick}
      onPointerLeave={() => setHover(null)}
    >
      <svg
        viewBox="0 0 100 28"
        preserveAspectRatio="none"
        role="img"
        aria-label={label}
        className="h-full w-full overflow-visible"
      >
        {segments.map((points) => (
          <Fragment key={points}>
            <polygon
              points={sparklineArea(points)}
              fill="var(--color-primary)"
              fillOpacity={0.22}
              stroke="none"
            />
            <polyline
              points={points}
              fill="none"
              stroke="var(--color-primary)"
              strokeWidth={new Set(points.split(" ")).size === 1 ? 3 : 1.5}
              strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          </Fragment>
        ))}
      </svg>
      {time !== undefined && (
        <>
          <span
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-0 border-l border-dashed border-muted-foreground"
            style={{ left: `${x}%` }}
          />
          {y !== null && (
            <span
              aria-hidden="true"
              className="pointer-events-none absolute size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary ring-2 ring-background"
              style={{ left: `${x}%`, top: `${y}%` }}
            />
          )}
          <span
            aria-hidden="true"
            className="pointer-events-none absolute bottom-full z-30 mb-1.5 rounded-lg border bg-background px-2.5 py-1.5 font-mono text-xs whitespace-nowrap shadow-xl"
            style={{
              left: `${x}%`,
              transform: `translateX(${x < 20 ? "0" : x > 80 ? "-100%" : "-50%"})`,
            }}
          >
            {clockTime(time)} · {value === null ? "no report" : format(value)}
          </span>
        </>
      )}
    </div>
  );
}
