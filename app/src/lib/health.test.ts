import { describe, expect, it } from "vitest";

import type { CheckRecord, NodeRecord } from "../types";
import { bySeverity, fleetSummary, nodeHealth, usageLevel } from "./health";

const NOW = Date.parse("2026-09-28T12:00:00Z");
const seen = (secondsAgo: number) =>
  new Date(NOW - secondsAgo * 1000)
    .toISOString()
    .replace("T", " ")
    .slice(0, 19);

function node(extra: Partial<NodeRecord> = {}): NodeRecord {
  return {
    id: "n1",
    name: "web-01",
    hostname: "web-01",
    architecture: "amd64",
    operating_system: "linux",
    agent_version: "0.6.0",
    last_seen_at: seen(10),
    enrolled_at: seen(86_400),
    disabled_at: null,
    interval_seconds: 60,
    cpu_percent: 20,
    memory_used_bytes: 4,
    memory_total_bytes: 10,
    disk_used_bytes: 3,
    disk_total_bytes: 10,
    load_1: 0.2,
    uptime_seconds: 100,
    created_at: seen(86_400),
    ...extra,
  } as NodeRecord;
}

function check(
  status: "UP" | "DOWN" | "UNKNOWN",
  extra: Partial<CheckRecord> = {},
): CheckRecord {
  return {
    id: `c-${status}`,
    node_id: "n1",
    name: "API",
    kind: "HTTP",
    target: "https://example.com",
    enabled: 1,
    status,
    timeout_seconds: 10,
    latency_ms: 40,
    last_checked_at: null,
    consecutive_failures: 0,
    last_message: null,
    ...extra,
  } as CheckRecord;
}

describe("usageLevel", () => {
  it("turns amber at 80% and red at 90%, and knows no level without data", () => {
    expect(usageLevel(79.9)).toBe("ok");
    expect(usageLevel(80)).toBe("warn");
    expect(usageLevel(89.9)).toBe("warn");
    expect(usageLevel(90)).toBe("critical");
    expect(usageLevel(null)).toBeNull();
  });
});

describe("nodeHealth", () => {
  it("is healthy when online, checks pass and usage is normal", () => {
    expect(nodeHealth(node(), [check("UP")], NOW)).toEqual({
      severity: "healthy",
      reasons: [],
    });
  });

  it("puts an offline node first in line, whatever it last reported", () => {
    expect(
      nodeHealth(
        node({ last_seen_at: seen(3600), disk_used_bytes: 10 }),
        [],
        NOW,
      ),
    ).toEqual({ severity: "critical", reasons: ["Offline"] });
  });

  it("names failing checks before resource pressure", () => {
    expect(
      nodeHealth(
        node({ memory_used_bytes: 8.8, disk_used_bytes: 9.3 }),
        [check("DOWN"), check("DOWN", { id: "c2" }), check("UP")],
        NOW,
      ),
    ).toEqual({
      severity: "critical",
      reasons: ["2 checks down", "Disk 93%", "RAM 88%"],
    });
  });

  it("warns on usage between 80% and 90% and ignores disabled checks", () => {
    expect(
      nodeHealth(
        node({ cpu_percent: 85 }),
        [check("DOWN", { enabled: 0 })],
        NOW,
      ),
    ).toEqual({ severity: "warning", reasons: ["CPU 85%"] });
  });

  it("keeps pending and disabled nodes out of the alarm", () => {
    expect(nodeHealth(node({ enrolled_at: null }), [], NOW).severity).toBe(
      "idle",
    );
    expect(nodeHealth(node({ disabled_at: seen(10) }), [], NOW).severity).toBe(
      "idle",
    );
  });
});

describe("bySeverity", () => {
  it("orders critical, warning, healthy, idle, then by name", () => {
    const rows = [
      { name: "b", severity: "healthy" },
      { name: "a", severity: "healthy" },
      { name: "z", severity: "critical" },
      { name: "m", severity: "idle" },
      { name: "k", severity: "warning" },
    ] as const;
    expect([...rows].sort(bySeverity).map((row) => row.name)).toEqual([
      "z",
      "k",
      "a",
      "b",
      "m",
    ]);
  });
});

describe("fleetSummary", () => {
  it("counts what the operator asks first", () => {
    const nodes = [
      node(),
      node({ id: "n2", last_seen_at: seen(3600) }),
      node({ id: "n3", enrolled_at: null }),
    ];
    const checks = [
      check("UP"),
      check("DOWN", { id: "c2" }),
      check("UP", { id: "c3", node_id: "n2" }),
    ];
    expect(fleetSummary(nodes, checks, NOW)).toEqual({
      nodes: { total: 3, online: 1, offline: 1 },
      checks: { total: 3, up: 1, down: 1, stale: 1 },
    });
  });
});
