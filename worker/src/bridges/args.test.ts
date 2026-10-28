import { describe, expect, it } from "vitest";

import {
  adminArgsValid,
  bridgeArgsValid,
  hasStackNetworkArgs,
  stackNetworkArgsValid,
} from "./args";

const KEY =
  "AAAAC3NzaC1lZDI1NTE5AAAAIN+aw2ekALRgy/qt38BoTs6eGn55s71g0oi0WM0vVl+z";

describe("a shared network's arguments", () => {
  it("creates a Contained or Full Access network on a private IPv4 subnet", () => {
    expect(
      bridgeArgsValid("create", { kind: "contained", subnet: "172.24.0.0/24" }),
    ).toBe(true);
    expect(
      bridgeArgsValid("create", { kind: "full", subnet: "172.23.0.0/16" }),
    ).toBe(true);
    expect(
      bridgeArgsValid("create", { kind: "full", subnet: "192.168.40.0/28" }),
    ).toBe(true);
    for (const args of [
      { kind: "open", subnet: "172.24.0.0/24" } as Record<string, string>,
      { kind: "contained", subnet: "172.24.0.0" },
      { kind: "contained", subnet: "172.24.0.5/24" },
      { kind: "contained", subnet: "8.8.8.0/24" },
      { kind: "contained", subnet: "10.0.0.0/8" },
      { kind: "contained", subnet: "172.24.0.0/30" },
      { kind: "contained", subnet: "172.24.0.0/24", extra: "1" },
      { kind: "contained" },
    ]) {
      expect(bridgeArgsValid("create", args), JSON.stringify(args)).toBe(false);
    }
  });

  it("removes a network with no arguments", () => {
    expect(bridgeArgsValid("remove", {})).toBe(true);
    expect(bridgeArgsValid("remove", { kind: "full" })).toBe(false);
    expect(bridgeArgsValid("deploy", {})).toBe(false);
  });
});

describe("an admin user's arguments", () => {
  it("names a user that is not root and one to four keys", () => {
    expect(adminArgsValid({ name: "musyaf", keys: `${KEY}:laptop` })).toBe(
      true,
    );
    expect(
      adminArgsValid({
        name: "musyaf",
        keys: [1, 2, 3, 4].map((n) => `${KEY}:k${n}`).join(","),
      }),
    ).toBe(true);
    for (const args of [
      { name: "root", keys: `${KEY}:laptop` } as Record<string, string>,
      { name: "Musyaf", keys: `${KEY}:laptop` },
      { name: "musyaf", keys: "" },
      { name: "musyaf", keys: `${KEY}:j5mus@laptop` },
      {
        name: "musyaf",
        keys: [1, 2, 3, 4, 5].map((n) => `${KEY}:k${n}`).join(","),
      },
      { name: "musyaf" },
      { name: "musyaf", keys: `${KEY}:laptop`, password: "x" },
    ]) {
      expect(adminArgsValid(args), JSON.stringify(args)).toBe(false);
    }
  });
});

describe("a stack's offers and reaches", () => {
  it("accepts well-formed lists, empty ones and no arguments at all", () => {
    expect(stackNetworkArgsValid({})).toBe(true);
    expect(stackNetworkArgsValid({ offers: "", peers: "" })).toBe(true);
    expect(
      stackNetworkArgsValid({
        offers: "apps-inner/web=3001/tcp,apps-inner/web=3002/udp",
        peers: "apps-inner/postgres.db:5432/tcp",
      }),
    ).toBe(true);
    expect(stackNetworkArgsValid({ peers: "apps-inner/postgres:5432" })).toBe(
      false,
    );
    expect(
      stackNetworkArgsValid({
        offers: Array(65).fill("apps-inner/web=1/tcp").join(","),
      }),
    ).toBe(false);
  });

  it("says when a stack uses them, so the 0.7.1 gate applies", () => {
    expect(hasStackNetworkArgs({ hostPorts: "3000/tcp" })).toBe(false);
    expect(hasStackNetworkArgs({ offers: "", peers: "" })).toBe(false);
    expect(hasStackNetworkArgs({ offers: "apps-inner/web=3001/tcp" })).toBe(
      true,
    );
  });
});
