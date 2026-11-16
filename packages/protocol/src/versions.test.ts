import { describe, expect, it } from "vitest";

import * as versions from "./versions";
import {
  ACCOUNTS_AGENT,
  agentKnowsAccounts,
  agentKnowsMemberKinds,
  agentSealsFromSender,
  agentSupported,
  compareVersions,
  MEMBER_KINDS_AGENT,
  MIN_AGENT_VERSION,
  SEAL_AGENT,
} from "./versions";

describe("agent versions", () => {
  it("orders release numbers numerically", () => {
    expect(compareVersions("0.5.10", "0.5.9")).toBeGreaterThan(0);
    expect(compareVersions("0.3.1", "0.3.1")).toBe(0);
  });

  it("supports only agent 0.7.20 and later, and builds from source", () => {
    expect(MIN_AGENT_VERSION).toBe("0.7.20");
    expect(agentSupported("0.7.20")).toBe(true);
    expect(agentSupported("0.7.21")).toBe(true);
    expect(agentSupported("0.10.0")).toBe(true);
    expect(agentSupported("0.7.19")).toBe(false);
    expect(agentSupported("0.7.2")).toBe(false);
    expect(agentSupported("0.6.14")).toBe(false);
    expect(agentSupported("dev")).toBe(true);
    expect(agentSupported(null)).toBe(false);
  });

  it("stores passkey owners from agent 0.7.22", () => {
    expect(ACCOUNTS_AGENT).toBe("0.7.22");
    expect(agentKnowsAccounts("0.7.22")).toBe(true);
    expect(agentKnowsAccounts("0.7.21")).toBe(false);
    expect(agentKnowsAccounts("dev")).toBe(true);
    expect(agentKnowsAccounts(null)).toBe(false);
  });

  it("knows laptops and exit nodes from agent 0.7.24", () => {
    expect(MEMBER_KINDS_AGENT).toBe("0.7.24");
    expect(agentKnowsMemberKinds("0.7.23")).toBe(false);
    expect(agentKnowsMemberKinds("0.7.24")).toBe(true);
    expect(agentKnowsMemberKinds("0.8.0")).toBe(true);
    expect(agentKnowsMemberKinds("dev")).toBe(true);
    expect(agentKnowsMemberKinds(null)).toBe(false);
  });

  it("binds a piece to its sender from agent 0.7.21", () => {
    expect(SEAL_AGENT).toBe("0.7.21");
    expect(agentSealsFromSender("0.7.21")).toBe(true);
    expect(agentSealsFromSender("0.7.20")).toBe(false);
    expect(agentSealsFromSender("dev")).toBe(true);
    expect(agentSealsFromSender(null)).toBe(false);
  });

  it("keeps the feature gates above the minimum and none below it", () => {
    expect(Object.keys(versions).sort()).toEqual([
      "ACCOUNTS_AGENT",
      "MEMBER_KINDS_AGENT",
      "MIN_AGENT_VERSION",
      "SEAL_AGENT",
      "agentKnowsAccounts",
      "agentKnowsMemberKinds",
      "agentSealsFromSender",
      "agentSupported",
      "compareVersions",
    ]);
  });
});
