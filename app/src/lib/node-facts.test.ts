import { describe, expect, it } from "vitest";

import { clockTime } from "./format";
import { systemFacts } from "./node-facts";
import type { NodeRecord } from "@/types";

const NOW = Date.parse("2026-10-24T09:00:00.000Z");

const pivox = (change: Partial<NodeRecord> = {}): NodeRecord => ({
  id: "n1",
  name: "pivox",
  hostname: "pivox",
  architecture: "arm64",
  operating_system: "Debian 12",
  agent_version: "0.6.13",
  last_seen_at: null,
  enrolled_at: null,
  disabled_at: null,
  interval_seconds: 60,
  cpu_percent: null,
  memory_used_bytes: null,
  memory_total_bytes: null,
  disk_used_bytes: null,
  disk_total_bytes: null,
  load_1: null,
  uptime_seconds: 12 * 86_400,
  created_at: "2026-09-01T00:00:00.000Z",
  update_requested_version: null,
  update_requested_at: null,
  auto_update: 1,
  ...change,
});

describe("the server page's system line", () => {
  it("say what the server is in one line", () => {
    expect(systemFacts(pivox(), NOW)).toEqual([
      "Debian 12 · arm64",
      "Up 12d",
      "Not connected",
      "Reports every 1m",
      "Agent 0.6.13",
    ]);
  });

  it("name the host only when it differs from the server", () => {
    expect(systemFacts(pivox({ hostname: "raspberrypi" }), NOW)[0]).toBe(
      "Host raspberrypi",
    );
  });

  it("say -- for what it does not know", () => {
    const facts = systemFacts(
      pivox({ uptime_seconds: null, agent_version: null }),
      NOW,
    );
    expect(facts).toContain("Up --");
    expect(facts).toContain("Agent --");
  });

  it("say since when it reports live", () => {
    const at = new Date(NOW - 60 * 60_000).toISOString();
    expect(systemFacts(pivox({ connected_at: at }), NOW)).toContain(
      `Live since ${clockTime(at)}`,
    );
  });
});
