import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceArea,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts";

import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { LEVEL_TEXT } from "@/components/meter";
import { clockTime, shortDate } from "@/lib/format";
import type { UsageLevel } from "@/lib/health";
import { cn } from "@/lib/utils";
import { isLonePoint, type Gap } from "@/lib/series";
import type { MetricRange } from "@/types";

interface ChartSeries {
  key: string;
  label: string;
}

export type ChartRow = { time: number } & Record<string, number | null>;

const COLORS = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)"];

const RANGE_LABEL: Record<MetricRange, string> = {
  "6h": "Last 6 Hours",
  "24h": "Last 24 Hours",
  "7d": "Last 7 Days",
};

export function MetricChart({
  id,
  title,
  value,
  summary,
  rows,
  gaps,
  from,
  to,
  range,
  series,
  max,
  level,
}: {
  id: string;
  title: string;
  value: string;
  summary: string;
  rows: ChartRow[];
  gaps: Gap[];
  from: number;
  to: number;
  range: MetricRange;
  series: ChartSeries[];
  max?: number;
  level?: UsageLevel | null;
}) {
  const config: ChartConfig = Object.fromEntries(
    series.map((item, index) => [
      item.key,
      { label: item.label, color: COLORS[index] },
    ]),
  );
  const tick = (time: number) =>
    range === "7d" ? shortDate(time) : clockTime(time);
  const empty = !rows.some((row) =>
    series.some((item) => typeof row[item.key] === "number"),
  );

  return (
    <figure className="min-w-0 rounded-lg border bg-card p-3">
      <figcaption className="flex items-baseline justify-between gap-2 text-[11px] text-muted-foreground">
        <span>{title}</span>
        <span>{RANGE_LABEL[range]}</span>
      </figcaption>
      <p
        className={cn(
          "mt-1 mb-2 truncate font-mono text-xl",
          level && level !== "ok" && LEVEL_TEXT[level],
        )}
      >
        {value}
      </p>
      {series.length > 1 && (
        <ul className="mb-2 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] text-muted-foreground">
          {series.map((item, index) => (
            <li key={item.key} className="flex items-center gap-1.5">
              <span
                aria-hidden="true"
                className="inline-block size-2 rounded-full"
                style={{ background: COLORS[index] }}
              />
              {item.label}
            </li>
          ))}
        </ul>
      )}
      <p className="sr-only">{`${title}, ${RANGE_LABEL[range].toLowerCase()}: ${summary}`}</p>
      {empty ? (
        <div className="flex h-32 items-center justify-center rounded-md border border-dashed text-xs text-muted-foreground">
          No reports in the {RANGE_LABEL[range].toLowerCase()}
        </div>
      ) : (
        <ChartContainer
          config={config}
          className="aspect-auto h-32 w-full"
          aria-hidden="true"
        >
          <AreaChart
            data={rows}
            margin={{ top: 4, right: 4, bottom: 0, left: 4 }}
            accessibilityLayer={false}
          >
            <defs>
              <pattern
                id={`hatch-${id}`}
                width="6"
                height="6"
                patternUnits="userSpaceOnUse"
                patternTransform="rotate(45)"
              >
                <line
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="6"
                  stroke="var(--border)"
                  strokeWidth="3"
                />
              </pattern>
            </defs>
            <CartesianGrid vertical={false} stroke="var(--border)" />
            <XAxis
              dataKey="time"
              type="number"
              scale="time"
              domain={[from, to]}
              tickFormatter={tick}
              tickLine={false}
              axisLine={false}
              minTickGap={48}
              fontSize={10}
            />
            <YAxis
              width={32}
              domain={max === undefined ? [0, "auto"] : [0, max]}
              ticks={max === 100 ? [0, 50, 100] : undefined}
              tickCount={3}
              tickFormatter={(tickValue: number) =>
                max === 100 ? `${tickValue}%` : String(tickValue)
              }
              tickLine={false}
              axisLine={false}
              fontSize={10}
            />
            {max === 100 && (
              <ReferenceLine
                y={90}
                stroke="var(--destructive)"
                strokeDasharray="3 3"
                strokeOpacity={0.5}
                ifOverflow="hidden"
              />
            )}
            {gaps.map((gap) => (
              <ReferenceArea
                key={`${gap.from}-${gap.to}`}
                x1={gap.from}
                x2={gap.to}
                fill={`url(#hatch-${id})`}
                fillOpacity={1}
                strokeOpacity={0}
                ifOverflow="hidden"
              />
            ))}
            <ChartTooltip
              cursor={{
                stroke: "var(--muted-foreground)",
                strokeDasharray: "3 3",
              }}
              content={
                <ChartTooltipContent
                  labelFormatter={(_, payload) => {
                    const time: unknown = payload[0]?.payload?.time;
                    return typeof time === "number"
                      ? `${shortDate(time)} ${clockTime(time)}`
                      : "";
                  }}
                />
              }
            />
            {series.map((item, index) => {
              const column = rows.map((row) => row[item.key] ?? null);
              return (
                <Area
                  key={item.key}
                  dataKey={item.key}
                  type="monotone"
                  stroke={`var(--color-${item.key})`}
                  strokeWidth={index === 0 ? 1.5 : 1.2}
                  fill={`var(--color-${item.key})`}
                  fillOpacity={index === 0 ? 0.14 : 0}
                  connectNulls={false}
                  isAnimationActive={false}
                  dot={({ index: at, cx, cy }) =>
                    isLonePoint(column, at) ? (
                      <circle
                        key={at}
                        cx={cx}
                        cy={cy}
                        r={2}
                        fill={`var(--color-${item.key})`}
                      />
                    ) : null
                  }
                  activeDot={{ r: 3 }}
                />
              );
            })}
          </AreaChart>
        </ChartContainer>
      )}
    </figure>
  );
}
