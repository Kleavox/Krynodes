import { describe, expect, it } from "vitest";

import { publicIpv4 } from "./address";

describe("publicIpv4", () => {
  it("keeps a global unicast IPv4", () => {
    for (const address of [
      "203.0.113.9",
      "198.51.100.7",
      "1.1.1.1",
      "100.63.255.255",
      "100.128.0.1",
      "172.15.255.255",
      "172.32.0.1",
      "169.253.1.1",
      "223.255.255.254",
    ]) {
      expect(publicIpv4(address)).toBe(address);
    }
  });

  it("drops every private, shared, loopback, link-local, multicast and reserved address", () => {
    for (const address of [
      "0.0.0.0",
      "0.1.2.3",
      "10.88.37.4",
      "100.64.0.1",
      "100.127.255.255",
      "127.0.0.1",
      "169.254.1.1",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "224.0.0.1",
      "239.255.255.255",
      "240.0.0.1",
      "255.255.255.255",
    ]) {
      expect(publicIpv4(address)).toBeNull();
    }
  });

  it("drops IPv6 and anything that is not a plain dotted quad", () => {
    for (const value of [
      "2001:db8::1",
      "::ffff:203.0.113.9",
      "203.0.113",
      "203.0.113.256",
      "203.0.113.09",
      "203.0.113.9:51820",
      " 203.0.113.9",
      "",
      undefined,
      null,
    ]) {
      expect(publicIpv4(value)).toBeNull();
    }
  });
});
