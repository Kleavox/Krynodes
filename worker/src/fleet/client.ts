import { windowSize } from "../agent/windows";
import type { Env } from "../env";
import type { KrynodesContext } from "../routes/shared";
import type { LiveNode } from "./stream";

export const streamsOn = (env: Env) => Boolean(env.FLEET);

export function hubFor(env: Env, ownerId: string) {
  const namespace = env.FLEET!;
  return namespace.get(namespace.idFromName(ownerId));
}

export interface MailState {
  failedAt: string;
  error: string;
}

export async function fleetLive(
  env: Env,
  ownerId: string,
): Promise<{
  nodes: Record<string, LiveNode>;
  mail: MailState | null;
} | null> {
  if (!streamsOn(env)) return { nodes: {}, mail: null };
  try {
    const response = await hubFor(env, ownerId).fetch("https://fleet/live");
    if (!response.ok) throw new Error(`hub answered ${response.status}`);
    return (await response.json()) as {
      nodes: Record<string, LiveNode>;
      mail: MailState | null;
    };
  } catch (error) {
    console.error("[kry fleet]", error);
    return null;
  }
}

export async function pokeNodes(
  env: Env,
  ownerId: string,
  nodeIds: string[],
): Promise<void> {
  if (!streamsOn(env) || nodeIds.length === 0) return;
  try {
    await hubFor(env, ownerId).fetch("https://fleet/poke", {
      method: "POST",
      body: JSON.stringify({ nodeIds: [...new Set(nodeIds)] }),
    });
  } catch (error) {
    console.error("[kry fleet]", error);
  }
}

async function announce(
  env: Env,
  ownerId: string,
  topics: string[],
): Promise<void> {
  if (!streamsOn(env)) return;
  try {
    await hubFor(env, ownerId).fetch("https://fleet/announce", {
      method: "POST",
      body: JSON.stringify({ topics }),
    });
  } catch (error) {
    console.error("[kry fleet]", error);
  }
}

export function announceSoon(
  context: KrynodesContext,
  ownerId: string,
  topics: string[],
): void {
  const work = announce(context.env, ownerId, topics);
  try {
    context.executionCtx.waitUntil(work);
  } catch {
    work.catch(() => undefined);
  }
}

export function pokeSoon(
  context: KrynodesContext,
  ownerId: string,
  nodeIds: string[],
): void {
  const work = pokeNodes(context.env, ownerId, nodeIds);
  try {
    context.executionCtx.waitUntil(work);
  } catch {
    work.catch(() => undefined);
  }
}

const sqliteTime = (epochMs: number) =>
  new Date(epochMs).toISOString().replace("T", " ").slice(0, 19);

interface NodeRow {
  id: string;
  interval_seconds: number;
}

export function mergeLive<T extends NodeRow>(
  rows: T[],
  live: Record<string, LiveNode> | null,
): (T & { grace_seconds?: number })[] {
  return rows.map((row) => {
    if (live === null) {
      return {
        ...row,
        grace_seconds:
          windowSize(row.interval_seconds) / 1000 + 2 * row.interval_seconds,
      };
    }
    const entry = live[row.id];
    if (!entry) return row;
    return {
      ...row,
      last_seen_at: sqliteTime(entry.lastSeen),
      ...(Number.isFinite(entry.connectedAt)
        ? { connected_at: new Date(entry.connectedAt).toISOString() }
        : {}),
      agent_version: entry.agentVersion,
      hostname: entry.hostname,
      cpu_percent: entry.metrics.cpuPercent,
      memory_used_bytes: entry.metrics.memoryUsedBytes,
      memory_total_bytes: entry.metrics.memoryTotalBytes,
      disk_used_bytes: entry.metrics.diskUsedBytes,
      disk_total_bytes: entry.metrics.diskTotalBytes,
      load_1: entry.metrics.load1,
      uptime_seconds: entry.metrics.uptimeSeconds,
    };
  });
}
