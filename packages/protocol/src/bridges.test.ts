import { describe, expect, it } from "vitest";

import {
  ADMIN_KEY_ARG,
  ADMIN_NAME,
  agentActionSchema,
  agentActionsRequestSchema,
  bridgesReportSchema,
  isValidTarget,
  OFFER_ENTRY,
  PEER_ENTRY,
  serviceEntrySchema,
  stackNetworkSchema,
} from "./index";

const signedCommand = {
  grant: {
    grant: "Z3JhbnQ",
    credentialId: "Y3JlZA",
    authenticatorData: "YXV0aA",
    clientDataJSON: "Y2xpZW50",
    signature: "c2ln",
  },
  command: "Y29tbWFuZA",
  signature: "c2lnbmF0dXJl",
};

const action = (step: Record<string, unknown>) =>
  agentActionSchema.safeParse({
    id: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1b01",
    expiresAt: "2026-10-28T10:10:00.000Z",
    ...step,
  }).success;

const report = {
  networks: [
    {
      name: "apps-inner",
      kind: "contained",
      subnet: "172.24.0.0/24",
      members: [
        {
          project: "panel",
          service: "web",
          address: "172.24.0.3",
          offers: ["3001/tcp"],
          guest: false,
        },
        {
          project: "db",
          service: "postgres",
          address: "172.24.0.4",
          offers: ["5432/tcp"],
          guest: true,
        },
      ],
    },
    {
      name: "proxy",
      kind: "outside",
      subnet: null,
      members: [],
    },
  ],
  taken: [
    { range: "172.18.0.0/16", by: "panel_default" },
    { range: "192.168.1.0/24", by: "eth0", own: true },
  ],
  claimed: ["default-env_public"],
};

describe("shared Docker networks of agent 0.7.1", () => {
  it("creates and removes a network only with a signed command", () => {
    const create = { kind: "bridge", name: "apps-inner", action: "create" };
    expect(action({ ...create, signed: signedCommand })).toBe(true);
    expect(action(create)).toBe(false);
    expect(action({ ...create, action: "remove", signed: signedCommand })).toBe(
      true,
    );
    expect(action({ ...create, action: "deploy", signed: signedCommand })).toBe(
      false,
    );
    expect(isValidTarget("bridge", "default-env_public")).toBe(true);
    expect(isValidTarget("bridge", "bad/name")).toBe(false);
    expect(isValidTarget("bridge", "-dash")).toBe(false);
    expect(isValidTarget("bridge", "a".repeat(64))).toBe(false);
  });

  it("asks for an admin user on the server only, signed", () => {
    const admin = { kind: "host", name: "server", action: "admin" };
    expect(action({ ...admin, signed: signedCommand })).toBe(true);
    expect(action(admin)).toBe(false);
    expect(action({ ...admin, name: "docker", signed: signedCommand })).toBe(
      false,
    );
    expect(
      action({ ...admin, name: "ssh-keys-only", signed: signedCommand }),
    ).toBe(false);
    expect(action({ ...admin, name: "tailscale", signed: signedCommand })).toBe(
      false,
    );
  });

  it("applies and undoes No Root Login like the other recipes", () => {
    const recipe = { kind: "host", name: "no-root-login", action: "apply" };
    expect(action({ ...recipe, signed: signedCommand })).toBe(true);
    expect(action({ ...recipe, action: "undo", signed: signedCommand })).toBe(
      true,
    );
  });

  it("reports units that ran at boot or are not needed", () => {
    const entry = {
      kind: "systemd",
      name: "e2scrub_reap.service",
      since: null,
      system: true,
    };
    expect(
      serviceEntrySchema.safeParse({ ...entry, state: "boot" }).success,
    ).toBe(true);
    expect(
      serviceEntrySchema.safeParse({ ...entry, state: "unneeded" }).success,
    ).toBe(true);
    expect(
      serviceEntrySchema.safeParse({ ...entry, state: "sleeping" }).success,
    ).toBe(false);
  });

  it("reports the server's networks in the inventory", () => {
    expect(bridgesReportSchema.safeParse(report).success).toBe(true);
    const accepts = (bridges: unknown) =>
      agentActionsRequestSchema.safeParse({
        nodeId: "0b4f4f53-7d1c-4b55-9a39-2f0a0d6c1b02",
        inventory: { hash: "c".repeat(64), bridges },
      }).success;
    expect(accepts(report)).toBe(true);
    expect(accepts(null)).toBe(true);
    expect(
      accepts({ ...report, networks: Array(33).fill(report.networks[1]) }),
    ).toBe(false);
    expect(
      bridgesReportSchema.safeParse({
        ...report,
        networks: [{ ...report.networks[0], kind: "open" }],
      }).success,
    ).toBe(false);
    expect(
      bridgesReportSchema.safeParse({
        ...report,
        taken: [{ range: "10.0.0.0/8", by: "eth0", own: "yes" }],
      }).success,
    ).toBe(false);
  });

  it("carries a stack's offers and reaches on a shared network", () => {
    const network = { serves: [], reaches: [], private: [] };
    expect(stackNetworkSchema.safeParse(network).success).toBe(true);
    expect(
      stackNetworkSchema.safeParse({
        ...network,
        offers: ["apps-inner/web=3001/tcp"],
        peers: ["apps-inner/postgres.db:5432/tcp"],
      }).success,
    ).toBe(true);
    expect(
      stackNetworkSchema.safeParse({
        ...network,
        peers: ["apps-inner/postgres:5432"],
      }).success,
    ).toBe(false);
    expect(OFFER_ENTRY.test("apps-inner/web=3001/tcp")).toBe(true);
    expect(OFFER_ENTRY.test("apps-inner/web=3001")).toBe(false);
    expect(PEER_ENTRY.test("apps-inner/resolver.adns:53/udp")).toBe(true);
    expect(PEER_ENTRY.test("apps-inner/postgres.DB:5432/tcp")).toBe(false);
  });

  it("names an admin user and its keys the way the server reads them", () => {
    expect(ADMIN_NAME.test("user1")).toBe(true);
    expect(ADMIN_NAME.test("_ops-1")).toBe(true);
    expect(ADMIN_NAME.test("User1")).toBe(false);
    expect(ADMIN_NAME.test("1ops")).toBe(false);
    expect(ADMIN_NAME.test("a".repeat(33))).toBe(false);
    expect(
      ADMIN_KEY_ARG.test(
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl:laptop",
      ),
    ).toBe(true);
    expect(ADMIN_KEY_ARG.test("AAAA:user1@laptop")).toBe(false);
    expect(ADMIN_KEY_ARG.test("AAAA")).toBe(false);
  });
});
