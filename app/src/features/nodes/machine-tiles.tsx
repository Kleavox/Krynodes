import { useState, type ComponentProps } from "react";

import { FilterChips } from "@/components/filter-chips";
import { LEVEL_TEXT } from "@/components/meter";
import { MetricChart, type ChartRow } from "@/components/metric-chart";
import { Sparkline } from "@/components/sparkline";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { useNodeMetrics } from "@/lib/api";
import {
  formatBytes,
  graceSeconds,
  metricText,
  percentage,
} from "@/lib/format";
import { usageLevel, type UsageLevel } from "@/lib/health";
import { errorMessage } from "@/lib/http";
import { rangeText } from "@/lib/node-facts";
import { findGaps, seriesSummary, withGapBreaks } from "@/lib/series";
import { cn } from "@/lib/utils";
import type { MetricRange, NodeMetrics, NodeRecord } from "@/types";

const RANGES: { value: MetricRange; label: string }[] = [
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

export function readRange(value: string | null): MetricRange {
  return RANGES.find((option) => option.value === value)?.value ?? "6h";
}

type TileId = "cpu" | "mem" | "disk" | "load";

const round1 = (value: number | null) =>
  value === null ? null : Math.round(value * 10) / 10;

const percent = (value: number) => `${metricText(value)}%`;

function machineData(data: NodeMetrics, node: NodeRecord) {
  const from = Date.parse(data.from);
  const to = Date.parse(data.to);
  const rows: ChartRow[] = data.points.map((point) => ({
    time: Date.parse(point.t),
    cpu: round1(point.cpu),
    mem: round1(percentage(point.memUsed, point.memTotal)),
    disk: round1(percentage(point.diskUsed, point.diskTotal)),
    load1: round1(point.load1),
    load5: round1(point.load5),
    load15: round1(point.load15),
  }));
  const gaps = findGaps(
    rows.map((row) => row.time),
    Math.max(data.bucketSeconds, graceSeconds(node.interval_seconds)),
    { from, to },
    data.bucketSeconds,
  );
  const chartRows = withGapBreaks(rows, gaps, (time) => ({
    time,
    cpu: null,
    mem: null,
    disk: null,
    load1: null,
    load5: null,
    load15: null,
  }));
  const values = (key: string) => rows.map((row) => row[key] ?? null);
  const memory = percentage(node.memory_used_bytes, node.memory_total_bytes);
  const disk = percentage(node.disk_used_bytes, node.disk_total_bytes);
  const last = data.points.at(-1);
  const loads = [last?.load1, last?.load5, last?.load15].map((value) =>
    metricText(value ?? null),
  );
  const tiles: Record<
    TileId,
    {
      title: string;
      value: string;
      small: string;
      level: UsageLevel | null;
      key: string;
      max: number;
    }
  > = {
    cpu: {
      title: "CPU",
      value: metricText(node.cpu_percent, "%"),
      small: rangeText(values("cpu"), "%"),
      level: usageLevel(node.cpu_percent),
      key: "cpu",
      max: 100,
    },
    mem: {
      title: "RAM",
      value: metricText(memory, "%"),
      small: `${formatBytes(node.memory_used_bytes)} / ${formatBytes(node.memory_total_bytes)}`,
      level: usageLevel(memory),
      key: "mem",
      max: 100,
    },
    disk: {
      title: "Disk",
      value: metricText(disk, "%"),
      small: `${formatBytes(node.disk_used_bytes)} / ${formatBytes(node.disk_total_bytes)}`,
      level: usageLevel(disk),
      key: "disk",
      max: 100,
    },
    load: {
      title: "Load",
      value: loads.join(" "),
      small: "1 · 5 · 15",
      level: null,
      key: "load1",
      max: Math.max(
        1,
        ...values("load1").filter((value): value is number => value !== null),
      ),
    },
  };
  const charts: Record<TileId, ComponentProps<typeof MetricChart>> = {
    cpu: {
      id: "cpu",
      title: "CPU",
      value: tiles.cpu.value,
      level: tiles.cpu.level,
      summary: seriesSummary(values("cpu"), percent),
      series: [{ key: "cpu", label: "CPU %" }],
      max: 100,
      gaps,
      from,
      to,
      range: data.range,
      rows: chartRows,
    },
    mem: {
      id: "mem",
      title: "RAM",
      value: `${tiles.mem.small} · ${tiles.mem.value}`,
      level: tiles.mem.level,
      summary: seriesSummary(values("mem"), percent),
      series: [{ key: "mem", label: "RAM %" }],
      max: 100,
      gaps,
      from,
      to,
      range: data.range,
      rows: chartRows,
    },
    disk: {
      id: "disk",
      title: "Disk",
      value: `${tiles.disk.small} · ${tiles.disk.value}`,
      level: tiles.disk.level,
      summary: seriesSummary(values("disk"), percent),
      series: [{ key: "disk", label: "Disk %" }],
      max: 100,
      gaps,
      from,
      to,
      range: data.range,
      rows: chartRows,
    },
    load: {
      id: "load",
      title: "Load 1 · 5 · 15",
      value: loads.join(" · "),
      summary: seriesSummary(values("load1"), (value) => metricText(value)),
      series: [
        { key: "load1", label: "Load 1m" },
        { key: "load5", label: "Load 5m" },
        { key: "load15", label: "Load 15m" },
      ],
      gaps,
      from,
      to,
      range: data.range,
      rows: chartRows,
    },
  };
  return {
    tiles,
    charts,
    values,
    times: rows.map((row) => row.time),
  };
}

function RangeChips({
  range,
  onRange,
}: {
  range: MetricRange;
  onRange: (range: MetricRange) => void;
}) {
  return (
    <FilterChips
      label="Time Range"
      value={range}
      options={RANGES}
      onChange={onRange}
    />
  );
}

export function MachineTiles({
  node,
  range,
  onRange,
  reported = false,
}: {
  node: NodeRecord;
  range: MetricRange;
  onRange: (range: MetricRange) => void;
  reported?: boolean;
}) {
  const query = useNodeMetrics(node.id, range);
  const [open, setOpen] = useState<TileId | null>(null);
  const machine = query.data ? machineData(query.data, node) : null;
  return (
    <section aria-labelledby="node-machine">
      <div className="mb-2 flex min-h-8 items-center gap-2">
        <h2
          id="node-machine"
          className="text-xs font-medium text-muted-foreground"
        >
          Machine{reported && " · reported by the server itself"}
        </h2>
        <span className="ml-auto">
          <RangeChips range={range} onRange={onRange} />
        </span>
      </div>
      {!machine ? (
        query.isError ? (
          <p
            role="alert"
            className="rounded-lg border p-4 text-sm text-destructive"
          >
            Metric history could not be loaded: {errorMessage(query.error)}
          </p>
        ) : (
          <div className="grid grid-cols-2 gap-2">
            {[0, 1, 2, 3].map((key) => (
              <Skeleton key={key} className="h-24" />
            ))}
          </div>
        )
      ) : (
        <div className="grid grid-cols-2 gap-2">
          {(Object.keys(machine.tiles) as TileId[]).map((id) => {
            const tile = machine.tiles[id];
            return (
              <button
                key={id}
                type="button"
                onClick={() => setOpen(id)}
                aria-label={`${tile.title} ${tile.value}. Open its chart`}
                className="min-w-0 rounded-lg border bg-card p-2.5 text-left transition-colors hover:bg-card-hover"
              >
                <span className="flex items-baseline justify-between gap-2 text-[11px] text-muted-foreground">
                  <span>{tile.title}</span>
                  <span className="truncate font-mono">{tile.small}</span>
                </span>
                <span
                  className={cn(
                    "block truncate font-mono text-lg",
                    tile.level && tile.level !== "ok" && LEVEL_TEXT[tile.level],
                  )}
                >
                  {tile.value}
                </span>
                <Sparkline
                  values={machine.values(tile.key)}
                  times={machine.times}
                  max={tile.max}
                  label={`${tile.title}, ${range}`}
                  format={
                    id === "load" ? (value) => metricText(value) : percent
                  }
                  className="h-7"
                />
              </button>
            );
          })}
        </div>
      )}
      <Dialog
        open={open !== null && machine !== null}
        onOpenChange={(next) => !next && setOpen(null)}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {open && machine ? machine.tiles[open].title : "Machine"} on{" "}
              {node.name}
            </DialogTitle>
            <DialogDescription className="sr-only">
              The chart over the chosen time range.
            </DialogDescription>
          </DialogHeader>
          <RangeChips range={range} onRange={onRange} />
          {open && machine && <MetricChart {...machine.charts[open]} />}
        </DialogContent>
      </Dialog>
    </section>
  );
}
