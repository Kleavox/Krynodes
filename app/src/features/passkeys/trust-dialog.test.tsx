import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Device, FleetNode } from "@/types";

import { applyTrust, trustPlan, unreported } from "./trust-dialog";

const device = (id: string, name: string): Device => ({
  id,
  name,
  alg: -7,
  publicKey: `key-${id}`,
  synced: false,
  createdAt: "2026-11-22T10:00:00.000Z",
  trusted: true,
});

const laptop = device("laptop", "Laptop");
const phone = device("phone", "Phone");

const server = (
  name: string,
  core: string[],
  access = core,
  online = true,
): FleetNode => ({
  id: `id-${name}`,
  name,
  hostname: null,
  os: null,
  arch: null,
  version: "0.8.0",
  online,
  lastSeenAt: null,
  trust: { version: 4, core, access },
  update: null,
  kind: "server",
  address: null,
  via: null,
  ms: null,
  request: null,
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("trust on servers", () => {
  it("removing the last passkey of a server is blocked before signing", async () => {
    const get = vi.fn();
    vi.stubGlobal("navigator", { credentials: { get } });
    vi.stubGlobal("fetch", vi.fn());
    const nodes = [server("server-1", ["laptop"])];
    expect(trustPlan(laptop, [laptop, phone], nodes, new Set())).toBe(
      "server-1 would have no passkey left.",
    );
    await expect(
      applyTrust(new QueryClient(), {
        device: laptop,
        devices: [laptop, phone],
        nodes,
        wanted: new Set(),
        origin: "https://kry.example.test",
      }),
    ).rejects.toThrow("server-1 would have no passkey left.");
    expect(get).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("blocks a change that leaves a server no passkey that can act on it", () => {
    const nodes = [server("server-1", ["laptop", "phone"], ["laptop"])];
    expect(trustPlan(laptop, [laptop, phone], nodes, new Set())).toBe(
      "server-1 would have no passkey that can act on it.",
    );
  });

  it("blocks a change for a server that is offline", () => {
    const nodes = [server("server-1", ["laptop"], ["laptop"], false)];
    expect(
      trustPlan(phone, [laptop, phone], nodes, new Set(["id-server-1"])),
    ).toBe("server-1 is offline.");
  });

  it("plans one change per server that changes, one version ahead", () => {
    const nodes = [
      server("server-1", ["laptop"]),
      server("server-2", ["laptop", "phone"]),
      server("server-3", ["laptop"]),
    ];
    const plan = trustPlan(
      phone,
      [laptop, phone],
      nodes,
      new Set(["id-server-1", "id-server-3"]),
    );
    expect(plan).toEqual([
      {
        node: nodes[0],
        version: 5,
        core: [
          { id: "laptop", name: "Laptop", alg: -7, publicKey: "key-laptop" },
          { id: "phone", name: "Phone", alg: -7, publicKey: "key-phone" },
        ],
        access: { "id-server-1": ["laptop", "phone"] },
        adds: true,
      },
      {
        node: nodes[1],
        version: 5,
        core: [
          { id: "laptop", name: "Laptop", alg: -7, publicKey: "key-laptop" },
        ],
        access: { "id-server-2": ["laptop"] },
        adds: false,
      },
      {
        node: nodes[2],
        version: 5,
        core: [
          { id: "laptop", name: "Laptop", alg: -7, publicKey: "key-laptop" },
          { id: "phone", name: "Phone", alg: -7, publicKey: "key-phone" },
        ],
        access: { "id-server-3": ["laptop", "phone"] },
        adds: true,
      },
    ]);
  });

  it("blocks a change when a server trusts a passkey this page does not list", () => {
    const nodes = [server("server-1", ["laptop", "gone"])];
    expect(
      trustPlan(phone, [laptop, phone], nodes, new Set(["id-server-1"])),
    ).toBe("server-1 trusts a passkey that is not listed here.");
  });

  it("names the servers left out because they have not reported their trust", () => {
    const silent = (name: string) => ({ ...server(name, []), trust: null });
    expect(unreported([server("server-1", ["laptop"])])).toBeNull();
    expect(
      unreported([server("server-1", ["laptop"]), silent("server-2")]),
    ).toBe("server-2 has not reported its trust yet, so it is not listed.");
    expect(unreported([silent("server-2"), silent("server-3")])).toBe(
      "server-2, server-3 have not reported their trust yet, so they are not listed.",
    );
  });
});
