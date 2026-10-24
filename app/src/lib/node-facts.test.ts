import { describe, expect, it } from "vitest";

import { rangeText, systemFacts } from "./node-facts";
import type { NodeRecord } from "@/types";

const io = (change: Partial<NodeRecord> = {}): NodeRecord => ({
  id: "n1",
  name: "io",
  hostname: "io",
  architecture: "amd64",
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
  uptime_seconds: 37 * 86_400 + 5 * 3_600,
  created_at: "2026-09-01T00:00:00.000Z",
  update_requested_version: null,
  update_requested_at: null,
  auto_update: 1,
  connected_at: "2026-10-24T08:00:00.000Z",
  ...change,
});

describe("the server page's facts", () => {
  it("say what the server is in one line of words", () => {
    expect(systemFacts(io())).toBe(
      "Debian 12 · amd64 · Up 37 days · Reports every minute · Agent 0.6.13",
    );
  });

  it("name the host only when it differs from the server", () => {
    expect(systemFacts(io({ hostname: "io-sg1" }))).toBe(
      "Debian 12 · amd64 · Up 37 days · Reports every minute · Agent 0.6.13 · Host io-sg1",
    );
  });

  it("never say Not connected or Live since", () => {
    const line = systemFacts(io({ connected_at: undefined }));
    expect(line).not.toContain("Not connected");
    expect(line).not.toContain("Live since");
  });

  it("count short spans in hours and minutes, intervals in words", () => {
    expect(
      systemFacts(io({ uptime_seconds: 1, interval_seconds: 300 })),
    ).toContain("Up 1 second · Reports every 5 minutes");
    expect(
      systemFacts(io({ uptime_seconds: 5 * 3_600, interval_seconds: 30 })),
    ).toContain("Up 5 hours · Reports every 30 seconds");
    expect(systemFacts(io({ uptime_seconds: 90 * 60 }))).toContain("Up 1 hour");
  });

  it("leave out what it does not know", () => {
    expect(
      systemFacts(
        io({
          uptime_seconds: null,
          agent_version: null,
          operating_system: null,
        }),
      ),
    ).toBe("amd64 · Reports every minute");
  });
});

describe("a machine tile's small figure", () => {
  it("says the lowest and highest in the range", () => {
    expect(rangeText([12.4, null, 63.2, 30], "%")).toBe("12–63%");
    expect(rangeText([0.3, 0.5], "")).toBe("0.3–0.5");
  });

  it("says one value once, and -- with nothing measured", () => {
    expect(rangeText([40, 40], "%")).toBe("40%");
    expect(rangeText([null, null], "%")).toBe("--");
  });
});
