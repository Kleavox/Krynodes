import { describe, expect, it } from "vitest";

import type { DeviceRecord } from "../types";
import { agentState, removalReady } from "./agent";

const NOW = Date.parse("2026-09-28T12:00:00Z");
const ago = (minutes: number) => new Date(NOW - minutes * 60_000).toISOString();

function node(
  version: string | null,
  requested: string | null = null,
  at: string | null = null,
  attempts = 1,
) {
  return {
    agent_version: version,
    update_requested_version: requested,
    update_requested_at: at,
    update_attempts: attempts,
  };
}

describe("agentState", () => {
  it("is unknown without a known release or a real agent version", () => {
    expect(agentState(node("0.5.1"), null, NOW)).toBe("unknown");
    expect(agentState(node("dev"), "0.5.2", NOW)).toBe("unknown");
    expect(agentState(node(null), "0.5.2", NOW)).toBe("unknown");
  });

  it("is current at or past the latest release", () => {
    expect(agentState(node("0.5.2"), "0.5.2", NOW)).toBe("current");
  });

  it("offers a remote update to agents that can still connect", () => {
    expect(agentState(node("0.5.1"), "0.5.2", NOW)).toBe("available");
  });

  it("calls an agent before 0.5.0 unsupported, since it can no longer connect", () => {
    expect(agentState(node("0.4.1"), "0.6.2", NOW)).toBe("unsupported");
    expect(agentState(node("0.3.0"), "0.5.2", NOW)).toBe("unsupported");
    expect(agentState(node("0.2.4", "0.5.2", ago(3)), "0.5.2", NOW)).toBe(
      "unsupported",
    );
    expect(agentState(node("0.3.0"), null, NOW)).toBe("unsupported");
  });

  it("keeps updating while Krynodes retries, and fails after the last attempt", () => {
    const state = (minutes: number, attempts: number) =>
      agentState(node("0.5.1", "0.5.2", ago(minutes), attempts), "0.5.2", NOW);
    expect(state(3, 1)).toBe("updating");
    expect(state(16, 1)).toBe("updating");
    expect(state(16, 3)).toBe("failed");
    expect(state(21, 2)).toBe("failed");
  });

  it("ignores a request the agent already passed, as after an update by hand", () => {
    expect(agentState(node("0.5.3", "0.5.2", ago(60)), "0.5.3", NOW)).toBe(
      "current",
    );
    expect(agentState(node("0.5.2", "0.5.2", ago(60)), "0.5.3", NOW)).toBe(
      "available",
    );
  });
});

describe("removing Krynodes from a server with Delete node", () => {
  const laptop = {
    id: "laptop",
    fingerprint: "aaaaaaaaaaaaaaaa",
  } as DeviceRecord;
  const server = (version: string | null, minutesAgo = 0) => ({
    agent_version: version,
    disabled_at: null,
    enrolled_at: ago(600),
    last_seen_at: ago(minutesAgo),
    interval_seconds: 60,
  });
  const trust = { version: 1, core: [], access: [laptop.fingerprint] };

  it("needs an online server on agent 0.6.2 or newer that a device can sign for", () => {
    expect(removalReady(server("0.6.2"), trust, [laptop], NOW)).toBe(true);
    expect(removalReady(server("0.7.0"), trust, [laptop], NOW)).toBe(true);
    expect(removalReady(server("0.6.1"), trust, [laptop], NOW)).toBe(false);
    expect(removalReady(server("dev"), trust, [laptop], NOW)).toBe(false);
    expect(removalReady(server("0.6.2", 10), trust, [laptop], NOW)).toBe(false);
    expect(removalReady(server("0.6.2"), null, [laptop], NOW)).toBe(false);
    expect(
      removalReady(server("0.6.2"), { ...trust, access: [] }, [laptop], NOW),
    ).toBe(false);
  });
});
