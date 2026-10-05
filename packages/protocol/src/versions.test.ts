import { describe, expect, it } from "vitest";

import {
  agentSupported,
  compareVersions,
  MIN_AGENT_VERSION,
  STACKS_AGENT,
} from "./versions";

describe("agent versions", () => {
  it("orders release numbers numerically", () => {
    expect(compareVersions("0.5.10", "0.5.9")).toBeGreaterThan(0);
    expect(compareVersions("0.3.1", "0.3.1")).toBe(0);
  });

  it("supports releases from the minimum on and builds from source", () => {
    expect(MIN_AGENT_VERSION).toBe("0.3.1");
    expect(agentSupported("0.3.1")).toBe(true);
    expect(agentSupported("0.10.0")).toBe(true);
    expect(agentSupported("0.3.0")).toBe(false);
    expect(agentSupported("0.2.4")).toBe(false);
    expect(agentSupported("dev")).toBe(true);
    expect(agentSupported(null)).toBe(false);
  });
});

describe("stacks agent", () => {
  it("is the first 0.4 release", () => {
    expect(STACKS_AGENT).toBe("0.4.0");
  });
});
