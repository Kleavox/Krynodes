import type { AgentHeartbeat, CheckResult } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import { drain, fold, liveView, newState, resumeWindow } from "./stream";

const NODE = "11111111-1111-4111-8111-111111111111";
const WINDOW = 300_000;
const BASE = Math.floor(Date.parse("2026-10-01T08:00:00Z") / WINDOW) * WINDOW;

const beat = (cpu: number | null, uptime = 100): AgentHeartbeat => ({
  nodeId: NODE,
  hostname: "server-1",
  operatingSystem: "linux",
  architecture: "amd64",
  agentVersion: "0.3.0",
  metrics: {
    cpuPercent: cpu,
    memoryUsedBytes: 4,
    memoryTotalBytes: 8,
    diskUsedBytes: 1,
    diskTotalBytes: 2,
    load1: 0.5,
    load5: 0.4,
    load15: 0.3,
    uptimeSeconds: uptime,
  },
});

const up: CheckResult = {
  checkId: "c1",
  status: "UP",
  latencyMs: 30,
  message: null,
};
const down: CheckResult = {
  checkId: "c1",
  status: "DOWN",
  latencyMs: null,
  message: "refused",
};

describe("stream state", () => {
  it("writes the server row on the first message only, then folds the window", () => {
    const first = fold(
      newState(NODE, "owner", 60),
      beat(10),
      [up],
      BASE + 5_000,
    );
    expect(first.writeNode).toBe(true);
    expect(first.flushed).toBeNull();
    const second = fold(first.state, beat(30, 160), [down], BASE + 65_000);
    expect(second.writeNode).toBe(false);
    expect(second.flushed).toBeNull();
    const third = fold(second.state, beat(null, 220), [up], BASE + 125_000);
    expect(third.state.lastSeen).toBe(BASE + 125_000);
    expect(third.state.window).toMatchObject({
      start: new Date(BASE).toISOString(),
      samples: 3,
      checks: { c1: ["DOWN", null, "refused"] },
    });
  });

  it("flushes the finished window with averages when a new one starts", () => {
    let state = fold(
      newState(NODE, "owner", 60),
      beat(10),
      [up],
      BASE + 5_000,
    ).state;
    state = fold(state, beat(30, 160), [up], BASE + 65_000).state;
    const next = fold(state, beat(50, 400), [up], BASE + WINDOW + 5_000);
    expect(next.writeNode).toBe(true);
    expect(next.flushed).toEqual({
      start: new Date(BASE).toISOString(),
      samples: 2,
      metrics: {
        cpuPercent: 20,
        memoryUsedBytes: 4,
        memoryTotalBytes: 8,
        diskUsedBytes: 1,
        diskTotalBytes: 2,
        load1: 0.5,
        load5: 0.4,
        load15: 0.3,
        uptimeSeconds: 160,
      },
      checks: { c1: ["UP", 30] },
    });
    expect(next.state.window).toMatchObject({
      start: new Date(BASE + WINDOW).toISOString(),
      samples: 1,
    });
  });

  it("resumes a window already started in D1, keeping a failure", () => {
    const resumed = resumeWindow(
      newState(NODE, "owner", 60),
      {
        window_start: new Date(BASE).toISOString(),
        samples: 2,
        cpu_percent: 40,
        memory_used_bytes: 6,
        memory_total_bytes: 8,
        disk_used_bytes: 1,
        disk_total_bytes: 2,
        load_1: 1,
        load_5: 1,
        load_15: 1,
        uptime_seconds: 90,
        checks: JSON.stringify({ c1: ["DOWN", null, "refused"] }),
      },
      BASE + 150_000,
    );
    const folded = fold(resumed, beat(10), [up], BASE + 160_000);
    const drained = drain(folded.state);
    expect(drained.flushed).toMatchObject({
      samples: 3,
      checks: { c1: ["DOWN", null, "refused"] },
      metrics: { cpuPercent: 30, uptimeSeconds: 100 },
    });
    expect(
      resumeWindow(newState(NODE, "owner", 60), null, BASE).window,
    ).toBeNull();
    expect(
      resumeWindow(
        newState(NODE, "owner", 60),
        {
          window_start: new Date(BASE - WINDOW).toISOString(),
          samples: 1,
          cpu_percent: 1,
          memory_used_bytes: 1,
          memory_total_bytes: 1,
          disk_used_bytes: 1,
          disk_total_bytes: 1,
          load_1: 1,
          load_5: 1,
          load_15: 1,
          uptime_seconds: 1,
          checks: "{}",
        },
        BASE + 10_000,
      ).window,
    ).toBeNull();
  });

  it("flushes the open window on close and empties it", () => {
    const state = fold(
      newState(NODE, "owner", 60),
      beat(10),
      [up],
      BASE + 5_000,
    ).state;
    const drained = drain(state);
    expect(drained.flushed?.samples).toBe(1);
    expect(drained.state.window).toBeNull();
    expect(drain(drained.state).flushed).toBeNull();
  });

  it("shows the live view of connected nodes", () => {
    const state = fold(
      newState(NODE, "owner", 60),
      beat(10),
      [up],
      BASE + 5_000,
    ).state;
    expect(liveView([state, newState("other", "owner", 60)])).toEqual({
      [NODE]: {
        lastSeen: BASE + 5_000,
        connectedAt: state.connectedAt,
        agentVersion: "0.3.0",
        hostname: "server-1",
        metrics: beat(10).metrics,
      },
    });
  });
});
