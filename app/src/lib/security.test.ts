import { describe, expect, it } from "vitest";

import type { SecurityReport } from "../types";
import {
  firewallName,
  firewallPorts,
  fromUtcHour,
  protectionDetail,
  protectionsNotice,
  recipeChoices,
  recommended,
  toUtcHour,
  worst,
} from "./security";

const report = (over: Partial<SecurityReport> = {}): SecurityReport => ({
  checkedAt: "2026-10-05T10:00:00.000Z",
  findings: [],
  recipes: [],
  lockdown: false,
  rebootHour: null,
  ...over,
});

describe("the security check on screen", () => {
  it("shows the worst finding as the server's mark", () => {
    expect(worst(null)).toBeNull();
    expect(
      worst(
        report({
          findings: [{ id: "ssh-keys", severity: "note", detail: "x" }],
        }),
      ),
    ).toBe("ok");
    expect(
      worst(
        report({
          findings: [
            { id: "updates-off", severity: "warning", detail: "x" },
            { id: "ssh-keys", severity: "note", detail: "x" },
          ],
        }),
      ),
    ).toBe("warning");
    expect(
      worst(
        report({
          findings: [
            { id: "updates-off", severity: "warning", detail: "x" },
            { id: "ssh-password", severity: "serious", detail: "x" },
          ],
        }),
      ),
    ).toBe("serious");
  });

  it("offers each recipe only when it can work", () => {
    const choices = recipeChoices(
      report({
        recipes: ["fail2ban"],
        findings: [{ id: "ssh-no-keys", severity: "warning", detail: "x" }],
      }),
    );
    expect(
      choices.map((choice) => [choice.id, choice.applied, choice.blocked]),
    ).toEqual([
      ["security-updates", false, null],
      ["reboot-window", false, null],
      [
        "ssh-keys-only",
        false,
        "First let root or a sudo user log in over SSH with a key.",
      ],
      ["fail2ban", true, null],
      ["firewall", false, null],
    ]);
    expect(
      recipeChoices(
        report({
          findings: [{ id: "dns-stub", severity: "note", detail: "x" }],
        }),
      ).some((choice) => choice.id === "free-port-53"),
    ).toBe(true);
  });

  it("recommends the four safest recipes that are still off and can run", () => {
    expect(
      recommended(
        report({
          recipes: ["fail2ban"],
          findings: [{ id: "ssh-no-keys", severity: "warning", detail: "x" }],
        }),
      ),
    ).toEqual(["security-updates", "reboot-window"]);
    expect(
      recommended(
        report({
          recipes: [
            "security-updates",
            "reboot-window",
            "ssh-keys-only",
            "fail2ban",
          ],
        }),
      ),
    ).toEqual([]);
  });

  it("reads the ports a firewall should keep open", () => {
    const found = report({
      findings: [
        {
          id: "public-ports",
          severity: "warning",
          detail:
            "Listening on public addresses outside Krynodes: 80/tcp (nginx), 5432/tcp (postgres), 8080/tcp (web-1)",
        },
      ],
    });
    expect(firewallPorts(found)).toEqual(["80/tcp", "5432/tcp", "8080/tcp"]);
    expect(firewallPorts(report())).toEqual([]);
  });

  it("turns a local hour into the server's UTC hour and back", () => {
    expect(toUtcHour(3, -420)).toBe(20);
    expect(fromUtcHour(20, -420)).toBe(3);
    expect(toUtcHour(23, 60)).toBe(0);
    expect(fromUtcHour(0, 60)).toBe(23);
  });
});

describe("protections on other systems", () => {
  const rocky = {
    family: "rhel" as const,
    name: "Rocky Linux 11.0",
    verified: false,
    checked: "8 to 10",
  };

  it("says when protections cannot run or must be confirmed", () => {
    expect(protectionsNotice(report())).toBeNull();
    expect(
      protectionsNotice(
        report({
          platform: {
            family: null,
            name: "Alpine Linux 3.20.3",
            verified: false,
            checked: "",
          },
        }),
      ),
    ).toBe("Protections support Debian, Ubuntu and RHEL-family servers.");
    expect(
      protectionsNotice(
        report({
          platform: rocky,
          findings: [
            {
              id: "os-unverified",
              severity: "note",
              detail:
                "Rocky Linux 11 is newer than the versions Krynodes has checked (8 to 10).",
            },
          ],
        }),
      ),
    ).toBe(
      "Rocky Linux 11 is newer than the versions Krynodes has checked (8 to 10). Turning a protection on asks you to confirm.",
    );
    expect(
      protectionsNotice(report({ platform: { ...rocky, verified: true } })),
    ).toBeNull();
  });

  it("names the firewall of the family", () => {
    expect(firewallName(report())).toBe("ufw");
    expect(firewallName(report({ platform: rocky }))).toBe("firewalld");
  });
});

describe("what each protection does, per system", () => {
  it("names the tools of the server's family", () => {
    const rhel = report({
      platform: {
        family: "rhel",
        name: "Rocky Linux 9.4",
        verified: true,
        checked: "8 to 10",
      },
    });
    expect(protectionDetail("security-updates", report())).toBe(
      "Installs security updates every day with unattended-upgrades.",
    );
    expect(protectionDetail("security-updates", rhel)).toBe(
      "Installs security updates every day with dnf.",
    );
    expect(protectionDetail("firewall", rhel)).toMatch(/^Turns on firewalld /u);
    expect(protectionDetail("fail2ban", rhel)).toBe(
      "Blocks addresses that keep failing to log in over SSH. Installs fail2ban from EPEL where the system needs it.",
    );
    expect(protectionDetail("firewall", report())).toMatch(/^Turns on ufw /u);
  });

  it("names the accounts that keep SSH when passwords stop", () => {
    const keyed = report({
      findings: [
        {
          id: "ssh-keys",
          severity: "note",
          detail: "SSH keys for root, deploy",
        },
      ],
    });
    expect(protectionDetail("ssh-keys-only", keyed)).toBe(
      "SSH stops accepting passwords. root and deploy keep logging in with their keys; an account without a key loses SSH. If you get locked out, Krynodes can turn passwords back on.",
    );
    expect(protectionDetail("ssh-keys-only", report())).toBe(
      "SSH stops accepting passwords; keys keep working. If you get locked out, Krynodes can turn passwords back on.",
    );
  });
});
