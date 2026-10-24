import { describe, expect, it } from "vitest";

import { listAddresses, type AddressColumns } from "./addresses";

const at = (minutes: number) =>
  new Date(
    Date.parse("2026-10-24T06:00:00.000Z") + minutes * 60_000,
  ).toISOString();

const columns = (change: Partial<AddressColumns>): AddressColumns => ({
  ipv4: null,
  ipv4_at: null,
  ipv4_network: null,
  ipv4_owner: null,
  ipv6: null,
  ipv6_at: null,
  ipv6_network: null,
  ipv6_owner: null,
  interfaces: null,
  ...change,
});

const on = (...entries: [string, string][]) =>
  JSON.stringify(entries.map(([name, address]) => ({ name, address })));

const pivox = columns({
  ipv4: "203.0.113.12",
  ipv4_at: at(0),
  ipv4_network: "PT Telkom Indonesia",
  interfaces: on(["eth0", "192.168.1.5"]),
});

describe("a server's addresses", () => {
  it("mark a seen address the server does not hold as a router's", () => {
    expect(listAddresses(pivox, [])).toEqual([
      {
        label: "IPv4",
        family: 4,
        address: "203.0.113.12",
        router: true,
        network: "PT Telkom Indonesia",
        owner: null,
      },
    ]);
  });

  it("leave the server's own address untagged", () => {
    const io = columns({
      ipv4: "51.79.0.10",
      ipv4_at: at(0),
      interfaces: on(["eth0", "51.79.0.10"]),
    });
    expect(listAddresses(io, [])[0]).toMatchObject({ router: false });
  });

  it("show no tag before the agent sends interfaces", () => {
    expect(listAddresses({ ...pivox, interfaces: null }, [])[0]).toMatchObject({
      router: false,
    });
    expect(listAddresses({ ...pivox, interfaces: "{" }, [])[0]).toMatchObject({
      router: false,
    });
  });

  it("show no tag when the stored list is not one it can read", () => {
    for (const interfaces of [
      "{}",
      "null",
      "[]",
      '[{"iface":"eth0","ip":"192.168.1.5"}]',
    ]) {
      expect(listAddresses({ ...pivox, interfaces }, [])[0]).toMatchObject({
        router: false,
      });
    }
  });

  it("follow the owner's correction over detection", () => {
    expect(listAddresses({ ...pivox, ipv4_owner: "own" }, [])[0]).toMatchObject(
      { router: false, owner: "own" },
    );
    const own = columns({
      ipv6: "2001:db8::91c3",
      ipv6_at: at(0),
      ipv6_owner: "router",
      interfaces: on(["eth0", "2001:db8::91c3"]),
    });
    expect(listAddresses(own, [])[0]).toMatchObject({
      router: true,
      owner: "router",
    });
  });

  it("compare IPv6 in one form", () => {
    const written = columns({
      ipv6: "2001:DB8:0:0::91C3",
      ipv6_at: at(0),
      interfaces: on(["eth0", "2001:db8::91c3"]),
    });
    expect(listAddresses(written, [])[0]).toMatchObject({ router: false });
    const zeros = columns({
      ipv6: "2001:0db8::0091:c3",
      ipv6_at: at(0),
      interfaces: on(["eth0", "2001:db8::91:c3"]),
    });
    expect(listAddresses(zeros, [])[0]).toMatchObject({ router: false });
  });

  it("list VPN addresses inside the private ranges under their interface", () => {
    const vpn = {
      ...pivox,
      interfaces: on(["eth0", "192.168.1.5"], ["tailscale0", "100.101.102.7"]),
    };
    expect(listAddresses(vpn, ["100.64.0.0/10"])).toEqual([
      expect.objectContaining({ label: "IPv4" }),
      {
        label: "tailscale0",
        family: 4,
        address: "100.101.102.7",
        router: false,
        network: null,
        owner: null,
      },
    ]);
    expect(listAddresses(vpn, [])).toHaveLength(1);
  });

  it("drop a family the server stopped answering on", () => {
    const stale = columns({
      ipv4: "203.0.113.12",
      ipv4_at: at(360),
      ipv6: "2001:db8::91c3",
      ipv6_at: at(0),
    });
    expect(listAddresses(stale, []).map((entry) => entry.label)).toEqual([
      "IPv4",
    ]);
  });

  it("order IPv4, IPv6, then interfaces by name", () => {
    const many = columns({
      ipv4: "203.0.113.12",
      ipv4_at: at(0),
      ipv6: "2001:db8::91c3",
      ipv6_at: at(1),
      interfaces: on(
        ["wg0", "10.8.0.2"],
        ["tailscale0", "fd7a:115c:a1e0::7"],
        ["tailscale0", "100.101.102.7"],
        ["eth0", "2001:db8::91c3"],
      ),
    });
    expect(
      listAddresses(many, [
        "10.8.0.0/24",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
      ]).map((entry) => `${entry.label} ${entry.address}`),
    ).toEqual([
      "IPv4 203.0.113.12",
      "IPv6 2001:db8::91c3",
      "tailscale0 100.101.102.7",
      "tailscale0 fd7a:115c:a1e0::7",
      "wg0 10.8.0.2",
    ]);
  });

  it("still list VPN addresses when no family was seen", () => {
    const quiet = columns({
      interfaces: on(["tailscale0", "100.101.102.7"]),
    });
    expect(listAddresses(quiet, ["100.64.0.0/10"])).toEqual([
      expect.objectContaining({ label: "tailscale0" }),
    ]);
  });

  it("do not list a VPN address that is also the seen one", () => {
    const same = columns({
      ipv4: "100.101.102.7",
      ipv4_at: at(0),
      interfaces: on(["tailscale0", "100.101.102.7"]),
    });
    expect(
      listAddresses(same, ["100.64.0.0/10"]).map((entry) => entry.label),
    ).toEqual(["IPv4"]);
  });
});
