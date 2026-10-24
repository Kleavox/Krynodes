import type { MiddlewareHandler } from "hono";

import { quietByNode, type QuietSpan } from "../agent/quiet";
import { fleetLive, mergeLive } from "../fleet/client";
import { findOwnedNode, type KrynodesApp, type KrynodesEnv } from "./shared";

const RANGES = {
  "6h": { seconds: 21_600, bucket: 300 },
  "24h": { seconds: 86_400, bucket: 900 },
  "7d": { seconds: 604_800, bucket: 3_600 },
} as const;

type MetricRange = keyof typeof RANGES;

export function parseRange(value: string | undefined): MetricRange {
  return value !== undefined && Object.hasOwn(RANGES, value)
    ? (value as MetricRange)
    : "6h";
}

export function epochIso(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString();
}

interface BucketRow {
  bucket: number;
  cpu: number | null;
  mem_used: number | null;
  mem_total: number | null;
  disk_used: number | null;
  disk_total: number | null;
  load1: number | null;
  load5: number | null;
  load15: number | null;
  samples: number;
}

const BUCKETS_SQL = `
  SELECT (CAST(strftime('%s', window_start) AS INTEGER) / CAST(?1 AS INTEGER))
           * CAST(?1 AS INTEGER) AS bucket,
         AVG(cpu_percent) AS cpu,
         AVG(memory_used_bytes) AS mem_used,
         MAX(memory_total_bytes) AS mem_total,
         AVG(disk_used_bytes) AS disk_used,
         MAX(disk_total_bytes) AS disk_total,
         AVG(load_1) AS load1,
         AVG(load_5) AS load5,
         AVG(load_15) AS load15,
         SUM(samples) AS samples
  FROM node_windows
  WHERE node_id = ?2 AND window_start >= ?3 AND samples > 0
  GROUP BY bucket
  ORDER BY bucket`;

interface RecentRow {
  node_id: string;
  slot: number;
  slot_seconds: number;
  cpu: number | null;
  mem_used: number | null;
  mem_total: number | null;
  samples: number;
  uptime: number | null;
}

interface RecentNode {
  slotSeconds: number;
  slots: {
    t: string;
    cpu: number | null;
    memPct: number | null;
    samples: number;
  }[];
  quiet: QuietSpan[];
}

const RECENT_NODES_SQL = `
  SELECT id, interval_seconds, last_seen_at, security FROM nodes
  WHERE owner_user_id = ? AND enrolled_at IS NOT NULL AND disabled_at IS NULL`;

export const RECENT_SQL = `
  SELECT m.node_id,
         MAX(300, n.interval_seconds) AS slot_seconds,
         CAST(strftime('%s', m.window_start) AS INTEGER) / MAX(300, n.interval_seconds) AS slot,
         AVG(m.cpu_percent) AS cpu,
         AVG(m.memory_used_bytes) AS mem_used,
         MAX(m.memory_total_bytes) AS mem_total,
         SUM(m.samples) AS samples,
         MIN(m.uptime_seconds) AS uptime
  FROM nodes n
  JOIN node_windows m
    ON m.node_id = n.id
   AND m.samples > 0
   AND m.window_start >= strftime('%Y-%m-%dT%H:%M:%fZ',
         (CAST(strftime('%s', ?2) AS INTEGER) / MAX(300, n.interval_seconds) - 31)
           * MAX(300, n.interval_seconds),
         'unixepoch')
  WHERE n.owner_user_id = ?1 AND n.disabled_at IS NULL
  GROUP BY m.node_id, slot
  ORDER BY m.node_id, slot`;

export function registerMetricRoutes(
  app: KrynodesApp,
  requireAdmin: MiddlewareHandler<KrynodesEnv>,
): void {
  app.get("/api/nodes/:id/metrics", requireAdmin, async (context) => {
    const node = await findOwnedNode(
      context.env.DB,
      context.req.param("id"),
      context.get("identity").id,
    );
    if (!node) return context.json({ code: "NOT_FOUND" }, 404);

    const range = parseRange(context.req.query("range"));
    const { seconds, bucket } = RANGES[range];
    const to = new Date();
    const from = new Date(to.getTime() - seconds * 1000);
    const rows = await context.env.DB.prepare(BUCKETS_SQL)
      .bind(bucket, node.id, from.toISOString())
      .all<BucketRow>();

    return context.json({
      range,
      bucketSeconds: bucket,
      from: from.toISOString(),
      to: to.toISOString(),
      points: rows.results.map((row) => ({
        t: epochIso(row.bucket),
        cpu: row.cpu,
        memUsed: row.mem_used,
        memTotal: row.mem_total,
        diskUsed: row.disk_used,
        diskTotal: row.disk_total,
        load1: row.load1,
        load5: row.load5,
        load15: row.load15,
        samples: row.samples,
      })),
    });
  });

  app.get("/api/metrics/recent", requireAdmin, async (context) => {
    const owner = context.get("identity").id;
    const now = Date.now();
    const [rows, owned, live] = await Promise.all([
      context.env.DB.prepare(RECENT_SQL)
        .bind(owner, new Date(now).toISOString())
        .all<RecentRow>(),
      context.env.DB.prepare(RECENT_NODES_SQL).bind(owner).all<{
        id: string;
        interval_seconds: number;
        last_seen_at: string | null;
        security: string | null;
      }>(),
      fleetLive(context.env, owner),
    ]);
    const quiet = quietByNode(
      rows.results.map((row) => ({
        node_id: row.node_id,
        window_start: epochIso(row.slot * row.slot_seconds),
        uptime_seconds: row.uptime,
      })),
      mergeLive(owned.results, live?.nodes ?? null),
      now - 31 * 300_000,
      now,
    );

    const nodes: Record<string, RecentNode> = {};
    for (const row of rows.results) {
      const entry = (nodes[row.node_id] ??= {
        slotSeconds: row.slot_seconds,
        slots: [],
        quiet: quiet[row.node_id]?.quiet ?? [],
      });
      entry.slots.push({
        t: epochIso(row.slot * row.slot_seconds),
        cpu: row.cpu,
        memPct:
          row.mem_used !== null && row.mem_total !== null && row.mem_total > 0
            ? (row.mem_used / row.mem_total) * 100
            : null,
        samples: row.samples,
      });
    }
    return context.json({ nodes });
  });
}
