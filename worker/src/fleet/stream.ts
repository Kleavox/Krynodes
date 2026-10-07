import type { AgentHeartbeat, CheckResult } from "@krynodes/protocol";

import {
  mergeChecks,
  parseChecks,
  windowStart,
  type WindowChecks,
} from "../agent/windows";

type Metrics = AgentHeartbeat["metrics"];
type Beat = Omit<AgentHeartbeat, "results">;

const AVERAGED = [
  "cpuPercent",
  "memoryUsedBytes",
  "diskUsedBytes",
  "load1",
  "load5",
  "load15",
] as const;
const LATEST = ["memoryTotalBytes", "diskTotalBytes", "uptimeSeconds"] as const;
const WHOLE = new Set(["memoryUsedBytes", "diskUsedBytes"]);

type Averaged = (typeof AVERAGED)[number];
type Latest = (typeof LATEST)[number];

interface Accumulator {
  start: string;
  samples: number;
  sums: Partial<Record<Averaged, number>>;
  counts: Partial<Record<Averaged, number>>;
  latest: Partial<Record<Latest, number>>;
  checks: WindowChecks;
}

export interface StreamState {
  nodeId: string;
  ownerId: string;
  interval: number;
  connectedAt: number;
  lastSeen: number | null;
  beat: Beat | null;
  window: Accumulator | null;
  wroteNode: boolean;
  away?: boolean;
  left?: boolean;
}

export interface Flush {
  start: string;
  samples: number;
  metrics: Metrics;
  checks: WindowChecks;
}

export interface StoredWindow {
  window_start: string;
  samples: number;
  cpu_percent: number | null;
  memory_used_bytes: number | null;
  memory_total_bytes: number | null;
  disk_used_bytes: number | null;
  disk_total_bytes: number | null;
  load_1: number | null;
  load_5: number | null;
  load_15: number | null;
  uptime_seconds: number | null;
  checks: string;
}

export function newState(
  nodeId: string,
  ownerId: string,
  interval: number,
  connectedAt = Date.now(),
): StreamState {
  return {
    nodeId,
    ownerId,
    interval,
    connectedAt,
    lastSeen: null,
    beat: null,
    window: null,
    wroteNode: false,
  };
}

const emptyWindow = (start: string): Accumulator => ({
  start,
  samples: 0,
  sums: {},
  counts: {},
  latest: {},
  checks: {},
});

export function resumeWindow(
  state: StreamState,
  row: StoredWindow | null,
  now: number,
): StreamState {
  if (!row || row.window_start !== windowStart(now, state.interval)) {
    return state;
  }
  const stored: Record<Averaged, number | null> = {
    cpuPercent: row.cpu_percent,
    memoryUsedBytes: row.memory_used_bytes,
    diskUsedBytes: row.disk_used_bytes,
    load1: row.load_1,
    load5: row.load_5,
    load15: row.load_15,
  };
  const window = emptyWindow(row.window_start);
  window.samples = row.samples;
  for (const key of AVERAGED) {
    const value = stored[key];
    if (value === null || row.samples === 0) continue;
    window.sums[key] = value * row.samples;
    window.counts[key] = row.samples;
  }
  const latest: Record<Latest, number | null> = {
    memoryTotalBytes: row.memory_total_bytes,
    diskTotalBytes: row.disk_total_bytes,
    uptimeSeconds: row.uptime_seconds,
  };
  for (const key of LATEST) {
    const value = latest[key];
    if (value !== null) window.latest[key] = value;
  }
  window.checks = parseChecks(row.checks);
  return { ...state, window };
}

function flushOf(window: Accumulator): Flush {
  const metrics = {} as Record<keyof Metrics, number | null>;
  for (const key of AVERAGED) {
    const count = window.counts[key] ?? 0;
    const value = count > 0 ? (window.sums[key] ?? 0) / count : null;
    metrics[key] = value !== null && WHOLE.has(key) ? Math.round(value) : value;
  }
  for (const key of LATEST) metrics[key] = window.latest[key] ?? null;
  return {
    start: window.start,
    samples: window.samples,
    metrics: metrics as Metrics,
    checks: window.checks,
  };
}

function addSample(
  window: Accumulator,
  metrics: Metrics,
  accepted: CheckResult[],
): Accumulator {
  const next: Accumulator = {
    ...window,
    samples: window.samples + 1,
    sums: { ...window.sums },
    counts: { ...window.counts },
    latest: { ...window.latest },
    checks: mergeChecks(window.checks, accepted),
  };
  for (const key of AVERAGED) {
    const value = metrics[key];
    if (value === null) continue;
    next.sums[key] = (next.sums[key] ?? 0) + value;
    next.counts[key] = (next.counts[key] ?? 0) + 1;
  }
  for (const key of LATEST) {
    const value = metrics[key];
    if (value !== null) next.latest[key] = value;
  }
  return next;
}

export function fold(
  state: StreamState,
  heartbeat: AgentHeartbeat,
  accepted: CheckResult[],
  now: number,
): { state: StreamState; flushed: Flush | null; writeNode: boolean } {
  const start = windowStart(now, state.interval);
  const rolled = state.window !== null && state.window.start !== start;
  const flushed = rolled && state.window ? flushOf(state.window) : null;
  const window = rolled || !state.window ? emptyWindow(start) : state.window;
  const { results: _results, ...beat } = heartbeat;
  return {
    state: {
      ...state,
      lastSeen: now,
      beat,
      window: addSample(window, heartbeat.metrics, accepted),
      wroteNode: true,
    },
    flushed,
    writeNode: rolled || !state.wroteNode,
  };
}

export function drain(state: StreamState): {
  state: StreamState;
  flushed: Flush | null;
} {
  if (!state.window || state.window.samples === 0) {
    return { state: { ...state, window: null }, flushed: null };
  }
  return { state: { ...state, window: null }, flushed: flushOf(state.window) };
}

export interface LiveNode {
  lastSeen: number;
  connectedAt: number;
  agentVersion: string;
  hostname: string;
  metrics: Metrics;
}

export function liveView(states: StreamState[]): Record<string, LiveNode> {
  const view: Record<string, LiveNode> = {};
  for (const state of states) {
    if (state.lastSeen === null || !state.beat) continue;
    const current = view[state.nodeId];
    if (current && current.lastSeen >= state.lastSeen) continue;
    view[state.nodeId] = {
      lastSeen: state.lastSeen,
      connectedAt: state.connectedAt,
      agentVersion: state.beat.agentVersion,
      hostname: state.beat.hostname,
      metrics: state.beat.metrics,
    };
  }
  return view;
}
