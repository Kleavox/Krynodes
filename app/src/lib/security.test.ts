import { describe, expect, it } from "vitest";

import type { SecurityReport } from "../types";
import {
  firewallName,
  findingTone,
  firewallPorts,
  fromUtcHour,
  protectionDetail,
  protectionsNotice,
  protectionsText,
  rangeLines,
  recipeChoices,
  recommended,
  shownFindings,
  toUtcHour,
  updatesUntil,
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

describe("the protections in one line", () => {
  it("counts what is on, on outside Krynodes and off", () => {
    expect(protectionsText(report())).toBe(
      "Protections · 3 on outside Krynodes · 3 off",
    );
    expect(protectionsText(report({ recipes: ["fail2ban"] }))).toBe(
      "Protections · 1 on · 2 on outside Krynodes · 3 off",
    );
  });
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
      [
        "no-root-login",
        false,
        "First let a sudo user other than root log in over SSH with a key.",
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

  it("shows a protection set up by hand as on, without offering to change it", () => {
    const choices = recipeChoices(
      report({
        recipes: ["security-updates"],
        findings: [
          { id: "ssh-password", severity: "serious", detail: "x" },
          { id: "dns-stub", severity: "note", detail: "x" },
        ],
      }),
    );
    expect(
      choices.map((choice) => [choice.id, choice.applied, choice.outside]),
    ).toEqual([
      ["security-updates", true, false],
      ["reboot-window", false, false],
      ["ssh-keys-only", false, false],
      ["no-root-login", false, false],
      ["fail2ban", false, true],
      ["firewall", false, true],
      ["free-port-53", false, false],
    ]);
    expect(
      recommended(
        report({
          findings: [{ id: "ssh-password", severity: "serious", detail: "x" }],
        }),
      ),
    ).toEqual(["reboot-window", "ssh-keys-only"]);
  });

  it("does not take a missing SSH finding as SSH set up by hand", () => {
    expect(
      recipeChoices(report()).find((choice) => choice.id === "ssh-keys-only")
        ?.outside,
    ).toBe(false);
  });

  it("marks SSH keys as good news, not as a note", () => {
    expect(findingTone({ id: "ssh-keys", severity: "note", detail: "x" })).toBe(
      "ok",
    );
    expect(findingTone({ id: "dns-stub", severity: "note", detail: "x" })).toBe(
      "idle",
    );
    expect(
      findingTone({ id: "public-ports", severity: "warning", detail: "x" }),
    ).toBe("warn");
    expect(
      findingTone({ id: "ssh-password", severity: "serious", detail: "x" }),
    ).toBe("bad");
  });

  it("recommends the firewall too when no firewall is on", () => {
    expect(
      recommended(
        report({
          recipes: ["security-updates", "reboot-window", "ssh-keys-only"],
          findings: [
            { id: "fail2ban-off", severity: "note", detail: "x" },
            { id: "firewall-off", severity: "note", detail: "x" },
          ],
        }),
      ),
    ).toEqual(["fail2ban", "firewall"]);
  });

  it("leaves the port 53 note out of the list, sorted worst first, and says what freeing it is for", () => {
    const found = report({
      findings: [
        { id: "dns-stub", severity: "note", detail: "port 53" },
        { id: "ssh-keys", severity: "note", detail: "keys" },
        { id: "updates-off", severity: "warning", detail: "updates" },
      ],
    });
    expect(shownFindings(found).map((finding) => finding.id)).toEqual([
      "updates-off",
      "ssh-keys",
    ]);
    expect(
      recipeChoices(found).find((choice) => choice.id === "free-port-53")?.hint,
    ).toBe("Only for a DNS server such as AdGuard.");
  });

  it("recommends the four safest recipes that are still off and can run", () => {
    expect(
      recommended(
        report({
          recipes: ["fail2ban"],
          findings: [
            { id: "ssh-no-keys", severity: "warning", detail: "x" },
            { id: "updates-off", severity: "warning", detail: "x" },
          ],
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

describe("addresses that are not public", () => {
  it("takes one range per line and ignores blank lines", () => {
    expect(
      rangeLines(" 100.64.0.0/10 \r\n\n fd7a:115c:a1e0::/48\n   \n"),
    ).toEqual(["100.64.0.0/10", "fd7a:115c:a1e0::/48"]);
    expect(rangeLines("")).toEqual([]);
  });
});

describe("protections on other systems", () => {
  const rocky = {
    family: "rhel" as const,
    name: "Rocky Linux 11.0",
    id: "rocky",
    version: "11",
  };

  it("says when protections cannot run", () => {
    expect(protectionsNotice(report())).toBeNull();
    expect(
      protectionsNotice(
        report({
          platform: { family: null, name: "Alpine Linux 3.20.3" },
        }),
      ),
    ).toBe("Protections support Debian, Ubuntu and RHEL-family servers.");
    expect(protectionsNotice(report({ platform: rocky }))).toBeNull();
  });

  it("says until when the system gets updates", () => {
    expect(updatesUntil(report())).toBeNull();
    expect(
      updatesUntil(report({ platform: { ...rocky, endOfLife: "2028-06-30" } })),
    ).toBe("Updates until 30 Jun 2028");
    expect(
      updatesUntil(report({ platform: { ...rocky, endOfLife: null } })),
    ).toBe("Updates until --");
    expect(updatesUntil(report({ platform: rocky }))).toBe("Updates until --");
  });

  it("says nothing about updates for an agent that does not name its system", () => {
    expect(
      updatesUntil(
        report({ platform: { family: "debian", name: "Debian GNU/Linux 12" } }),
      ),
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

describe("no root login", () => {
  const keyed = (detail: string) =>
    report({
      findings: [
        { id: "ssh-keys", severity: "note", detail },
        {
          id: "root-login",
          severity: "note",
          detail: "Root can log in over SSH.",
        },
      ],
    });

  it("comes after SSH keys only and waits for a sudo user other than root", () => {
    const choices = recipeChoices(keyed("SSH keys for root"));
    const ids = choices.map((choice) => choice.id);
    expect(ids.indexOf("no-root-login")).toBe(ids.indexOf("ssh-keys-only") + 1);
    const choice = choices.find((each) => each.id === "no-root-login")!;
    expect(choice).toMatchObject({
      title: "No root login",
      applied: false,
      outside: false,
      blocked:
        "First let a sudo user other than root log in over SSH with a key.",
    });
    expect(
      recipeChoices(keyed("SSH keys for musyaf, root")).find(
        (each) => each.id === "no-root-login",
      )!.blocked,
    ).toBeNull();
    expect(recommended(keyed("SSH keys for musyaf, root"))).not.toContain(
      "no-root-login",
    );
    expect(
      recipeChoices(
        report({
          findings: [
            { id: "ssh-keys", severity: "note", detail: "SSH keys for musyaf" },
          ],
        }),
      ).find((each) => each.id === "no-root-login")!.outside,
    ).toBe(true);
  });

  it("says on its row who keeps logging in, until it is on", () => {
    const row = (findings: string, recipes: string[] = []) =>
      recipeChoices({ ...keyed(findings), recipes }).find(
        (each) => each.id === "no-root-login",
      )!;
    expect(row("SSH keys for musyaf, root").hint).toBe(
      "SSH stops letting root log in. musyaf keeps logging in with a key and uses sudo. If you get locked out, Krynodes can turn root login back on.",
    );
    expect(row("SSH keys for musyaf, root", ["no-root-login"])).toMatchObject({
      applied: true,
      hint: null,
    });
  });

  it("names who keeps logging in", () => {
    expect(
      protectionDetail("no-root-login", keyed("SSH keys for musyaf, root")),
    ).toBe(
      "SSH stops letting root log in. musyaf keeps logging in with a key and uses sudo. If you get locked out, Krynodes can turn root login back on.",
    );
    expect(
      protectionDetail(
        "no-root-login",
        keyed("SSH keys for budi, musyaf, root"),
      ),
    ).toBe(
      "SSH stops letting root log in. budi and musyaf keep logging in with a key and use sudo. If you get locked out, Krynodes can turn root login back on.",
    );
  });
});
