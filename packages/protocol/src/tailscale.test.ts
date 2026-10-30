import { describe, expect, it } from "vitest";

import {
  portSchema,
  ruleSchema,
  TAILSCALE,
  webhookBodySchema,
} from "./tailscale";

describe("Tailscale rules", () => {
  it("knows the servers' tag and the webhook's events", () => {
    expect(TAILSCALE.tag).toBe("tag:kry");
    expect(TAILSCALE.hook).toBe("/hooks/tailscale");
    expect(TAILSCALE.events).toEqual(["nodeCreated", "policyUpdate"]);
  });

  it("takes a port, a port of one protocol, a range or every port", () => {
    for (const port of ["53", "22/tcp", "53/udp", "8000-8100/tcp", "*"]) {
      expect(portSchema.safeParse(port).success, port).toBe(true);
    }
    for (const port of ["0", "65536", "9-3/tcp", "22/sctp", "tcp:22", ""]) {
      expect(portSchema.safeParse(port).success, port).toBe(false);
    }
  });

  it("names who reaches which server, and nothing for everything else", () => {
    const serverOne = "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1a93";
    expect(
      ruleSchema.safeParse({
        from: "devices",
        to: "servers",
        ports: ["22/tcp"],
      }).success,
    ).toBe(true);
    expect(
      ruleSchema.safeParse({ from: serverOne, to: serverOne, ports: ["53"] })
        .success,
    ).toBe(true);
    expect(ruleSchema.safeParse({ from: "devices", to: "rest" }).success).toBe(
      true,
    );
    expect(ruleSchema.safeParse({ raw: '{"src":["*"]}' }).success).toBe(true);
    expect(ruleSchema.safeParse({ from: "servers", to: "rest" }).success).toBe(
      false,
    );
    expect(
      ruleSchema.safeParse({ from: "devices", to: "servers", ports: [] })
        .success,
    ).toBe(false);
    expect(
      ruleSchema.safeParse({ from: "tag:kry", to: "servers", ports: ["22"] })
        .success,
    ).toBe(false);
  });

  it("reads up to 20 events in one webhook call", () => {
    const event = {
      timestamp: "2026-10-27T03:12:00Z",
      version: 1,
      type: "nodeCreated",
      tailnet: "tail0000.ts.net",
      message: "Node nas-7 created",
      data: { nodeID: "nXyZ", managedBy: "tag:kry" },
    };
    expect(webhookBodySchema.safeParse([event, event, event]).success).toBe(
      true,
    );
    expect(webhookBodySchema.safeParse(Array(21).fill(event)).success).toBe(
      false,
    );
    expect(webhookBodySchema.safeParse(event).success).toBe(false);
    expect(
      webhookBodySchema.safeParse([{ ...event, type: "test", data: null }])
        .success,
    ).toBe(true);
  });
});
