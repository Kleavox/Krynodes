import { describe, expect, it } from "vitest";

import * as versions from "./versions";
import {
  agentHasFeatures,
  agentSupported,
  FEATURE_AGENT,
  compareVersions,
  MIN_AGENT_VERSION,
} from "./versions";

describe("agent versions", () => {
  it("orders release numbers numerically", () => {
    expect(compareVersions("0.5.10", "0.5.9")).toBeGreaterThan(0);
    expect(compareVersions("0.3.1", "0.3.1")).toBe(0);
  });

  it("supports only agent 0.7.0 and later, and builds from source", () => {
    expect(MIN_AGENT_VERSION).toBe("0.7.0");
    expect(agentSupported("0.7.0")).toBe(true);
    expect(agentSupported("0.7.1")).toBe(true);
    expect(agentSupported("0.6.14")).toBe(false);
    expect(agentSupported("0.10.0")).toBe(true);
    expect(agentSupported("0.6.13")).toBe(false);
    expect(agentSupported("0.6.0")).toBe(false);
    expect(agentSupported("0.5.1")).toBe(false);
    expect(agentSupported("0.4.1")).toBe(false);
    expect(agentSupported("dev")).toBe(true);
    expect(agentSupported(null)).toBe(false);
  });

  it("gates the new features on agent 0.7.1", () => {
    expect(FEATURE_AGENT).toBe("0.7.1");
    expect(agentHasFeatures("0.7.1")).toBe(true);
    expect(agentHasFeatures("0.7.2")).toBe(true);
    expect(agentHasFeatures("0.7.0")).toBe(false);
    expect(agentHasFeatures("dev")).toBe(true);
    expect(agentHasFeatures(null)).toBe(false);
  });

  it("keeps one feature gate above the minimum and none below it", () => {
    expect(Object.keys(versions).sort()).toEqual([
      "FEATURE_AGENT",
      "MIN_AGENT_VERSION",
      "agentHasFeatures",
      "agentSupported",
      "compareVersions",
    ]);
  });
});
