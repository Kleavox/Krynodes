import { describe, expect, it } from "vitest";

import * as versions from "./versions";
import { agentSupported, compareVersions, MIN_AGENT } from "./versions";

describe("agent versions", () => {
  it("orders release numbers numerically", () => {
    expect(compareVersions("0.5.10", "0.5.9")).toBeGreaterThan(0);
    expect(compareVersions("0.3.1", "0.3.1")).toBe(0);
  });

  it("supports only agent 0.7.90 and later, and builds from source", () => {
    expect(MIN_AGENT).toBe("0.7.90");
    expect(agentSupported("0.7.90")).toBe(true);
    expect(agentSupported("0.7.91")).toBe(true);
    expect(agentSupported("0.8.0")).toBe(true);
    expect(agentSupported("0.10.0")).toBe(true);
    expect(agentSupported("0.7.89")).toBe(false);
    expect(agentSupported("0.7.25")).toBe(false);
    expect(agentSupported("0.7.9")).toBe(false);
    expect(agentSupported("dev")).toBe(true);
    expect(agentSupported(null)).toBe(false);
  });

  it("keeps no feature floor above the minimum", () => {
    expect(Object.keys(versions).sort()).toEqual([
      "MIN_AGENT",
      "agentSupported",
      "compareVersions",
    ]);
  });
});
