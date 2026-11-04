import { describe, expect, it } from "vitest";

import type { SecurityReport } from "../types";
import { securityAttention, securitySummary } from "./fleet-security";

const report = (over: Partial<SecurityReport> = {}): SecurityReport => ({
  checkedAt: "2026-10-05T10:00:00.000Z",
  findings: [],
  recipes: [],
  lockdown: false,
  rebootHour: null,
  ...over,
});

describe("the Security page", () => {
  it("lists every server's problems on top, the serious first, then in Fleet order", () => {
    const first = report({
      findings: [
        { id: "clock-unsynced", severity: "warning", detail: "clock" },
        { id: "reboot-pending", severity: "note", detail: "restart" },
        { id: "updates-off", severity: "warning", detail: "updates" },
      ],
    });
    const second = report({
      findings: [
        { id: "ssh-password", severity: "serious", detail: "passwords" },
        { id: "dns-stub", severity: "warning", detail: "port 53" },
      ],
    });
    expect(
      securityAttention([
        { node: "server-1", report: first },
        { node: "server-2", report: second },
      ]).map(({ node, finding }) => `${node} ${finding.id}`),
    ).toEqual([
      "server-2 ssh-password",
      "server-1 clock-unsynced",
      "server-1 updates-off",
    ]);
  });

  it("sums a server up in one row", () => {
    expect(
      securitySummary(
        report({
          platform: {
            family: "rhel",
            name: "Rocky Linux 10",
            id: "rocky",
            version: "10",
            endOfLife: null,
          },
          recipes: [
            "security-updates",
            "reboot-window",
            "ssh-keys-only",
            "no-root-login",
            "fail2ban",
            "firewall",
          ],
          firewall: {
            closed: true,
            open: [
              { port: 443, protocol: "tcp", from: "everyone" },
              { port: 8443, protocol: "tcp", from: "everyone" },
            ],
            other: [],
          },
          confinement: {
            system: "selinux",
            mode: "enforcing",
            enforced: null,
            complain: null,
            managed: true,
            restart: false,
            docker: true,
          },
          findings: [
            { id: "public-ports", severity: "warning", detail: "8080/tcp" },
            { id: "reboot-pending", severity: "note", detail: "restart" },
          ],
        }),
      ),
    ).toEqual({
      protections: "All 5 On",
      firewall: "firewalld · Closed · 2 ports",
      confinement: { title: "SELinux", status: "Enforcing" },
      toCheck: 1,
    });
  });

  it("counts the protections that are off and leaves out what it was not told", () => {
    expect(
      securitySummary(
        report({
          recipes: ["security-updates"],
          findings: [
            { id: "fail2ban-off", severity: "note", detail: "fail2ban" },
            { id: "root-login", severity: "note", detail: "root" },
          ],
        }),
      ),
    ).toEqual({
      protections: "1 of 5 On",
      firewall: "ufw · On",
      confinement: null,
      toCheck: 0,
    });
    expect(
      securitySummary(
        report({
          platform: {
            family: null,
            name: "Arch Linux",
            id: "arch",
          },
        }),
      ).protections,
    ).toBe("Not supported");
  });
});
