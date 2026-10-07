import { describe, expect, it } from "vitest";

import * as versions from "./versions";
import {
  agentSupported,
  agentUpdatable,
  compareVersions,
  MIN_AGENT_VERSION,
  UPDATABLE_FROM,
} from "./versions";

describe("agent versions", () => {
  it("orders release numbers numerically", () => {
    expect(compareVersions("0.5.10", "0.5.9")).toBeGreaterThan(0);
    expect(compareVersions("0.3.1", "0.3.1")).toBe(0);
  });

  it("supports only agent 0.6.0 and later, and builds from source", () => {
    expect(MIN_AGENT_VERSION).toBe("0.6.0");
    expect(agentSupported("0.6.0")).toBe(true);
    expect(agentSupported("0.10.0")).toBe(true);
    expect(agentSupported("0.5.1")).toBe(false);
    expect(agentSupported("0.4.1")).toBe(false);
    expect(agentSupported("dev")).toBe(true);
    expect(agentSupported(null)).toBe(false);
  });

  it("still reaches agents from 0.5.0 on to tell them to update", () => {
    expect(UPDATABLE_FROM).toBe("0.5.0");
    expect(agentUpdatable("0.5.0")).toBe(true);
    expect(agentUpdatable("0.5.1")).toBe(true);
    expect(agentUpdatable("0.6.0")).toBe(true);
    expect(agentUpdatable("0.4.1")).toBe(false);
    expect(agentUpdatable("dev")).toBe(true);
    expect(agentUpdatable(undefined)).toBe(false);
  });

  it("keeps no feature gates below the minimum", () => {
    expect(Object.keys(versions).sort()).toEqual([
      "MIN_AGENT_VERSION",
      "UPDATABLE_FROM",
      "agentSupported",
      "agentUpdatable",
      "compareVersions",
    ]);
  });
});
