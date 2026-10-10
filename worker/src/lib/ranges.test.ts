import { describe, expect, it } from "vitest";

import { filterListeners, inRanges, parseRange } from "./ranges";

describe("address ranges", () => {
  it("normalizes IPv4 and IPv6 ranges and masks host bits", () => {
    expect(parseRange("100.64.0.0/10")).toBe("100.64.0.0/10");
    expect(parseRange(" 10.8.0.7/24 ")).toBe("10.8.0.0/24");
    expect(parseRange("192.168.1.5")).toBe("192.168.1.5/32");
    expect(parseRange("fd7a:115c:a1e0::/48")).toBe("fd7a:115c:a1e0::/48");
    expect(parseRange("FD7A:115C:A1E0:0:0:0:0:1/48")).toBe(
      "fd7a:115c:a1e0::/48",
    );
    expect(parseRange("::/0")).toBe("::/0");
    expect(parseRange("2001:db8::1")).toBe("2001:db8::1/128");
  });

  it("refuses what is not a range", () => {
    for (const text of [
      "",
      "10.0.0.0/33",
      "256.0.0.0/8",
      "10.0.0/8",
      "fd7a::115c::1/48",
      "fd7a:115c:a1e0::/129",
      "example.com",
      "10.0.0.0/-1",
      "1.2.3.4/08x",
    ]) {
      expect(parseRange(text)).toBeNull();
    }
  });

  it("tells whether an address is inside", () => {
    const ranges = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"];
    expect(inRanges("100.79.66.29", ranges)).toBe(true);
    expect(inRanges("100.128.0.1", ranges)).toBe(false);
    expect(inRanges("fd7a:115c:a1e0::3a01:4235", ranges)).toBe(true);
    expect(inRanges("fd7a:115c:a1e1::1", ranges)).toBe(false);
    expect(inRanges("::ffff:100.79.66.29", ranges)).toBe(true);
    expect(inRanges("0.0.0.0", ranges)).toBe(false);
    expect(inRanges("*", ranges)).toBe(false);
    expect(inRanges("100.79.66.29", [])).toBe(false);
  });
});

describe("the public-address finding", () => {
  const listeners = [
    {
      address: "100.79.66.29",
      port: 57969,
      protocol: "tcp" as const,
      process: "tailscaled",
    },
    {
      address: "0.0.0.0",
      port: 41641,
      protocol: "udp" as const,
      process: "tailscaled",
    },
    {
      address: "0.0.0.0",
      port: 8080,
      protocol: "tcp" as const,
      process: "web-1",
    },
    { address: "::", port: 8080, protocol: "tcp" as const, process: "web-1" },
  ];
  const report = {
    checkedAt: "2026-10-10T09:00:00.000Z",
    findings: [
      {
        id: "public-ports",
        severity: "warning" as const,
        detail:
          "Listening on public addresses outside Krynodes: 57969/tcp (tailscaled), 41641/udp (tailscaled), 8080/tcp (web-1)",
      },
      { id: "ssh-keys", severity: "note" as const, detail: "SSH keys for vox" },
    ],
    listeners,
  };

  it("leaves out listeners inside the ranges", () => {
    expect(filterListeners(report, ["100.64.0.0/10"]).findings).toEqual([
      {
        id: "public-ports",
        severity: "warning",
        detail:
          "Listening on public addresses outside Krynodes: 41641/udp (tailscaled), 8080/tcp (web-1)",
      },
      { id: "ssh-keys", severity: "note", detail: "SSH keys for vox" },
    ]);
  });

  it("drops the finding when nothing public is left", () => {
    expect(
      filterListeners(report, ["0.0.0.0/0", "::/0"]).findings.map(
        (finding) => finding.id,
      ),
    ).toEqual(["ssh-keys"]);
  });

  it("keeps reports it cannot judge as they are", () => {
    expect(filterListeners(report, [])).toBe(report);
    const old = { ...report, listeners: undefined };
    expect(filterListeners(old, ["0.0.0.0/0"])).toBe(old);
  });
});
