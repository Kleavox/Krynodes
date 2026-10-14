import { describe, expect, it } from "vitest";

import { maskAddress, serverAddresses } from "./addresses";

const at = (minutes: number) =>
  new Date(
    Date.parse("2026-10-14T06:00:00.000Z") + minutes * 60_000,
  ).toISOString();

describe("server addresses", () => {
  it("lists the families the newest probe saw", () => {
    expect(
      serverAddresses({
        ipv4: "103.28.54.214",
        ipv4_at: at(0),
        ipv6: "2001:db8::8f2a",
        ipv6_at: at(1),
      }),
    ).toEqual([
      { family: 4, address: "103.28.54.214" },
      { family: 6, address: "2001:db8::8f2a" },
    ]);
  });

  it("drops a family the server stopped answering on", () => {
    expect(
      serverAddresses({
        ipv4: "103.28.54.214",
        ipv4_at: at(6 * 60),
        ipv6: "2001:db8::8f2a",
        ipv6_at: at(0),
      }),
    ).toEqual([{ family: 4, address: "103.28.54.214" }]);
  });

  it("has nothing before the agent ever checked", () => {
    expect(
      serverAddresses({ ipv4: null, ipv4_at: null, ipv6: null, ipv6_at: null }),
    ).toEqual([]);
    expect(serverAddresses({})).toEqual([]);
  });

  it("hides the middle of an address", () => {
    expect(maskAddress({ family: 4, address: "103.28.54.214" })).toBe(
      "103.•.•.214",
    );
    expect(maskAddress({ family: 6, address: "2001:db8:1:2::8f2a" })).toBe(
      "2001:•••:8f2a",
    );
    expect(maskAddress({ family: 6, address: "2400:6180::1" })).toBe(
      "2400:•••:1",
    );
  });
});
