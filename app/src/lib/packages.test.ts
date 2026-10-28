import type { TailscaleReport } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import type {
  ActionRecord,
  AptReport,
  NodeRecord,
  SecurityReport,
} from "../types";
import { clockTime } from "./format";
import { actionLine, historyText } from "./history";
import {
  aptOutput,
  busyText,
  changedLines,
  agentNeeded,
  finishedLines,
  historyLines,
  installLines,
  jobLines,
  onTheirOwn,
  outcomeOf,
  packageAttention,
  packageCommands,
  packageMenu,
  packagesBlocker,
  packagesHeader,
  packageText,
  parseVendorPaste,
  removeChoices,
  removeLines,
  repoLines,
  repoName,
  restartFacts,
  restartLine,
  retryDialog,
  runningJob,
  runningPackages,
  shownPackages,
  signedIn,
  signedInLines,
  signInRows,
  tailscaleLine,
  tookText,
  updateRow,
  updatesHeader,
  updatesLine,
  upgradeLines,
  type InstallPreview,
} from "./packages";

const NOW = Date.parse("2026-10-26T09:00:00.000Z");
const ago = (ms: number) => new Date(NOW - ms).toISOString();
const ahead = (ms: number) => new Date(NOW + ms).toISOString();
const DAY = 86_400_000;

const node = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "vps-2",
  agent_version: "0.7.0",
  disabled_at: null,
  enrolled_at: ago(30 * DAY),
  last_seen_at: ago(10_000),
  interval_seconds: 60,
} as NodeRecord;

const report: AptReport = {
  apt: true,
  system: "Debian 12 bookworm",
  codename: "bookworm",
  readAt: ago(60_000),
  checkedAt: ago(3 * 60_000),
  installed: 412,
  packages: [
    {
      name: "wireguard-tools",
      version: "1.0.20210914-1+b1",
      from: "Debian",
      by: "Krynodes",
      feature: "the private network",
      more: 0,
      held: false,
    },
    {
      name: "docker-ce",
      version: "5:27.3.1-1~debian.12",
      from: "Docker",
      by: "Krynodes",
      feature: "Docker",
      more: 4,
      held: false,
    },
    {
      name: "tailscale",
      version: "1.76.1",
      from: "Tailscale",
      by: "seld",
      feature: null,
      more: 0,
      held: false,
    },
    {
      name: "nodejs",
      version: "20.18.0",
      from: "NodeSource",
      by: "seld",
      feature: null,
      more: 0,
      held: true,
    },
    {
      name: "libc6",
      version: "2.36-9+deb12u8",
      from: "Debian",
      by: null,
      feature: null,
      more: 0,
      held: false,
    },
  ],
  updates: [
    {
      name: "openssl",
      from: "3.0.14-1~deb12u2",
      to: "3.0.15-1~deb12u1",
      source: "Debian Security",
      security: true,
      held: false,
      back: null,
    },
    {
      name: "tailscale",
      from: "1.76.1",
      to: "1.78.1",
      source: "Tailscale",
      security: false,
      held: false,
      back: null,
    },
    {
      name: "docker-ce",
      from: "27.3.1",
      to: "27.4.0",
      source: "Docker",
      security: false,
      held: false,
      back: { adds: ["docker-ce-rootless-extras"], removes: [] },
    },
    {
      name: "nodejs",
      from: "20.18.0",
      to: "20.19.1",
      source: "NodeSource",
      security: false,
      held: true,
      back: null,
    },
  ],
  sources: [],
  security: { on: true, lastRan: "2026-10-26T06:12:00.000Z" },
  restart: {
    since: "2026-10-26T08:41:00.000Z",
    running: "6.1.0-26-amd64",
    newest: "6.1.0-27-amd64",
    file: true,
    services: [],
  },
};

const action = (over: Partial<ActionRecord>): ActionRecord => ({
  id: "a",
  batchId: "b",
  position: 0,
  mode: "rolling",
  nodeId: node.id,
  kind: "apt",
  name: "system",
  action: "upgrade",
  status: "done",
  requestedBy: "seld@example.com",
  requestedAt: ago(120_000),
  deliverableAt: null,
  sentAt: ago(41_000),
  finishedAt: null,
  exitCode: null,
  output: null,
  deviceId: null,
  ...over,
});

const running: TailscaleReport = {
  state: "running",
  addresses: ["100.101.7.12"],
  name: "vps-2.tail4d2a.ts.net",
  keyExpiry: "2027-04-24T10:00:00.000Z",
};

describe("the 0.7.0 gate", () => {
  it("names the version a server runs", () => {
    expect(agentNeeded({ agent_version: "0.6.14" })).toBe(
      "Needs agent 0.7.0 or newer · it runs 0.6.14",
    );
    expect(agentNeeded({ agent_version: null })).toBe(
      "Needs agent 0.7.0 or newer · it runs --",
    );
    expect(agentNeeded({ agent_version: "0.7.0" })).toBeNull();
  });

  it("says why a change waits", () => {
    expect(
      packagesBlocker({ ...node, agent_version: "0.6.14" }, true, NOW),
    ).toBe("Needs agent 0.7.0");
    expect(
      packagesBlocker({ ...node, last_seen_at: ago(2 * 3_600_000) }, true, NOW),
    ).toBe("Waits until vps-2 is back online");
    expect(packagesBlocker(node, false, NOW)).toBe("Not Trusted Yet");
    expect(packagesBlocker(node, true, NOW)).toBeNull();
  });
});

describe("the Updates row and the page header", () => {
  it("reads like the mockup", () => {
    expect(
      updatesLine(
        {
          waiting: 3,
          security: 1,
          held: 0,
          checkedAt: ago(3 * 60_000),
          restart: report.restart,
        },
        NOW,
      ),
    ).toEqual({
      text: "3 waiting · 1 security · checked 3m ago",
      restart: "Restart for the new kernel",
    });
    expect(
      updatesLine(
        { waiting: 0, security: 0, held: 0, checkedAt: null, restart: null },
        NOW,
      ),
    ).toEqual({
      text: "Up to date",
      restart: null,
    });
    expect(updatesLine(null, NOW)).toBeNull();
    expect(
      updatesLine(
        {
          waiting: 0,
          security: 0,
          held: 0,
          checkedAt: null,
          restart: {
            ...report.restart!,
            running: "6.1.0-27-amd64",
            file: false,
            services: ["sshd.service"],
          },
        },
        NOW,
      )?.restart,
    ).toBe("sshd uses old libraries");
    expect(updatesHeader(report)).toBe(
      "Updates · 4 waiting · 1 security · 1 held",
    );
  });

  it("puts the server, the system and when it was checked in the header", () => {
    expect(packagesHeader(node, { report, readAt: ago(60_000) }, NOW)).toEqual({
      line: "vps-2 · Debian 12 bookworm · 412 installed · checked 3m ago",
      offline: null,
      noApt: null,
    });
    expect(
      packagesHeader(
        { ...node, last_seen_at: ago(2 * 3_600_000) },
        { report, readAt: ago(2 * 3_600_000) },
        NOW,
      ).offline,
    ).toBe("Read 2h ago · vps-2 is offline");
    expect(
      packagesHeader(
        node,
        { report: { apt: false, system: "Fedora Linux 41" }, readAt: null },
        NOW,
      ).noApt,
    ).toBe(
      "Packages works with apt: Debian, Ubuntu and Raspberry Pi OS. vps-2 runs Fedora Linux 41.",
    );
    expect(
      packagesHeader(
        node,
        { report: { ...report, checkedAt: null }, readAt: null },
        NOW,
      ).line,
    ).toBe("vps-2 · Debian 12 bookworm · 412 installed · checked --");
  });

  it("tags each update and says why one is held back", () => {
    expect(updateRow(report.updates[0]!)).toEqual({
      tag: "Security",
      versions: "3.0.14-1~deb12u2 → 3.0.15-1~deb12u1",
      note: null,
    });
    expect(updateRow(report.updates[2]!).note).toBe(
      "Needs a new package, docker-ce-rootless-extras. Upgrade All brings it along and says so first.",
    );
    expect(updateRow(report.updates[3]!)).toEqual({
      tag: "Held",
      versions: "20.18.0",
      note: "Stays at 20.18.0 by your choice. Upgrade All and the daily security updates leave it. · 20.19.1 out",
    });
    expect(
      updateRow({
        ...report.updates[2]!,
        back: { adds: [], removes: ["containerd"] },
      }).note,
    ).toBe("Would remove containerd. Upgrade All leaves it.");
  });

  it("opens the list on what was added here", () => {
    expect(
      shownPackages(report, { all: false, query: "" }).map(
        (entry) => entry.name,
      ),
    ).toEqual(["wireguard-tools", "docker-ce", "tailscale", "nodejs"]);
    expect(
      shownPackages(report, { all: true, query: "lib" }).map(
        (entry) => entry.name,
      ),
    ).toEqual(["libc6"]);
  });
});

describe("Restart Needed", () => {
  it("says what was read", () => {
    expect(restartFacts(report.restart!, NOW).read).toBe(
      "Running kernel 6.1.0-26-amd64, newest installed 6.1.0-27-amd64. Read from the server: the running kernel against the installed one, and /run/reboot-required.",
    );
    expect(restartFacts(report.restart!, NOW).since).toMatch(
      /^since \d\d:41$/u,
    );
  });

  it("names who restarts it", () => {
    expect(restartLine({ recipes: ["reboot-window"], rebootHour: 3 }, 0)).toBe(
      "Restarts at 03:00 by Restart When Needed",
    );
    expect(restartLine({ recipes: [], rebootHour: 3 }, 0)).toBe(
      "Restart When Needed is off; restart it yourself",
    );
    expect(
      onTheirOwn(report, { recipes: [], rebootHour: null }, NOW, 0),
    ).toEqual({
      security: {
        mark: "✓",
        title: "Installed every day",
        detail: [
          `unattended-upgrades · last ran ${clockTime(report.security.lastRan!)}`,
        ],
      },
      restarts: {
        mark: "·",
        title: "Never on their own",
        detail: ["You restart with Restart Server"],
      },
    });
    expect(
      onTheirOwn(
        { ...report, security: { on: false, lastRan: null } },
        { recipes: ["reboot-window"], rebootHour: 3 },
        NOW,
        0,
      ),
    ).toEqual({
      security: { mark: "·", title: "Off", detail: [] },
      restarts: {
        mark: "✓",
        title: "At 03:00 by Restart When Needed",
        detail: [],
      },
    });
  });
});

describe("the Tailscale row", () => {
  it("has the five states of the mockup", () => {
    expect(tailscaleLine(running, "vps-2", NOW)).toEqual({
      lines: [
        "100.101.7.12",
        "vps-2.tail4d2a.ts.net",
        "Key expires 24 Apr 2027",
      ],
      warn: false,
      action: null,
      after: null,
    });
    expect(
      tailscaleLine({ ...running, keyExpiry: null }, "pivox", NOW).lines.at(-1),
    ).toBe("Key does not expire");
    expect(
      tailscaleLine(
        { ...running, keyExpiry: ahead(3 * DAY), tags: ["tag:kry"] },
        "pivox",
        NOW,
      ),
    ).toEqual({
      lines: [
        "100.101.7.12",
        "vps-2.tail4d2a.ts.net",
        "tag:kry · key never expires",
      ],
      warn: false,
      action: null,
      after: null,
    });
    expect(
      tailscaleLine(
        {
          ...running,
          state: "needs-login",
          addresses: [],
          name: null,
          keyExpiry: null,
        },
        "vps-2",
        NOW,
      ),
    ).toEqual({
      lines: ["Installed, not signed in"],
      warn: false,
      action: "Sign In",
      after: null,
    });
    expect(
      tailscaleLine({ ...running, keyExpiry: ahead(11.5 * DAY) }, "io", NOW),
    ).toEqual({
      lines: ["Key expires in 12 days"],
      warn: true,
      action: "Sign In Again",
      after: ", or turn off key expiry for io in Tailscale's admin console",
    });
    expect(
      tailscaleLine(
        {
          ...running,
          state: "needs-login",
          keyExpiry: "2026-04-02T10:00:00.000Z",
        },
        "io",
        NOW,
      ),
    ).toEqual({
      lines: ["Key expired 2 Apr · io left your tailnet"],
      warn: true,
      action: "Sign In Again",
      after: null,
    });
    expect(
      tailscaleLine({ ...running, state: "stopped" }, "vps-2", NOW),
    ).toEqual({
      lines: [
        "tailscaled is not running",
        "Start it from Services. Signing in waits until it runs.",
      ],
      warn: true,
      action: null,
      after: null,
    });
  });
});

describe("the dialogs", () => {
  const nginx: InstallPreview = {
    what: "install",
    name: "nginx",
    installs: [
      { name: "nginx", version: "1.22.1-9+deb12u1" },
      { name: "nginx-common", version: "1.22.1-9+deb12u1" },
      { name: "libnginx-mod-http-geoip2", version: "1.22.1-9+deb12u1" },
    ],
    upgrades: [],
    removes: [],
    download: 634_880,
    disk: 1_992_294,
    services: [
      {
        unit: "nginx.service",
        ports: [{ port: 80, protocol: "tcp", open: false }],
      },
    ],
    unread: false,
    firewall: "ufw",
    refused: null,
  };

  it("say what an install does", () => {
    expect(installLines(nginx, "vps-2")).toEqual([
      {
        mark: "+",
        title: "Installs 3 packages",
        detail: [
          "nginx, nginx-common, libnginx-mod-http-geoip2",
          "620 KB to download, 1.9 MB on disk",
        ],
      },
      {
        mark: "!",
        title: "Starts nginx.service right away, and at every boot",
        detail: [
          "It listens on port 80. ufw on vps-2 keeps it closed from outside until you open the port.",
        ],
      },
      { mark: "✓", title: "Removes nothing, replaces nothing", detail: [] },
    ]);
    const unknown = installLines(
      {
        ...nginx,
        download: null,
        disk: null,
        services: [{ unit: "x.service", ports: null }],
        removes: ["apache2"],
      },
      "vps-2",
    );
    expect(unknown[0]!.detail[1]).toBe("-- to download, -- on disk");
    expect(unknown[1]!.detail).toEqual(["Its ports show once it runs."]);
    expect(unknown.at(-1)).toEqual({
      mark: "−",
      title: "Removes apache2",
      detail: [],
    });
    expect(
      installLines(
        { ...nginx, refused: "openssh-server is never removed" },
        "vps-2",
      ),
    ).toEqual([
      { mark: "!", title: "openssh-server is never removed", detail: [] },
    ]);
  });

  it("say what a removal takes along", () => {
    expect(removeChoices("tailscale", "vps-2")).toEqual([
      {
        id: "remove",
        title: "Remove",
        detail:
          "Keeps /var/lib/tailscale, so installing it again brings back the same machine on your tailnet",
      },
      {
        id: "purge",
        title: "Remove with Settings",
        detail:
          "Also deletes /var/lib/tailscale. vps-2 has to log in to Tailscale again as a new machine.",
      },
    ]);
    expect(
      removeLines(
        {
          what: "remove",
          name: "tailscale",
          removes: ["tailscale"],
          stops: ["tailscaled.service"],
          refused: null,
        },
        {
          nodeName: "vps-2",
          repository: true,
          tailscale: running,
          publicAddress: "51.79.0.11",
        },
      ),
    ).toEqual([
      {
        mark: "−",
        title: "Removes tailscale",
        detail: [
          "Its repository stays under Sources until you remove it there",
        ],
      },
      {
        mark: "!",
        title: "vps-2 leaves your tailnet",
        detail: [
          "SSH to 100.101.7.12 stops working; use the public address 51.79.0.11 instead. Krynodes keeps its own connection.",
        ],
      },
    ]);
  });

  it("say what an upgrade restarts before the button", () => {
    const { header, lines } = upgradeLines(
      {
        what: "upgrade",
        upgrades: [
          { name: "openssl", version: "3.0.15-1~deb12u1" },
          { name: "tailscale", version: "1.78.1" },
          { name: "docker-ce", version: "27.4.0" },
        ],
        adds: [{ name: "docker-ce-rootless-extras", version: "27.4.0" }],
        restarts: ["docker.service", "tailscaled.service"],
      },
      { nodeName: "vps-2", report, stacks: ["db"], reached: ["db"] },
    );
    expect(header).toBe("3 updates. Nothing is removed.");
    expect(lines).toEqual([
      {
        mark: "↑",
        title: "openssl, tailscale and docker-ce",
        detail: [
          "plus 1 new package docker-ce needs: docker-ce-rootless-extras",
        ],
      },
      {
        mark: "!",
        title: "Docker restarts",
        detail: [
          "Every stack on vps-2 stops for a few seconds: db. Other servers that reach db lose it meanwhile.",
        ],
      },
      {
        mark: "!",
        title: "tailscaled restarts",
        detail: [
          "The Tailscale link to vps-2 drops for a moment. Krynodes keeps its own connection.",
        ],
      },
      {
        mark: "·",
        title: "Leaves nodejs at 20.18.0, held by you.",
        detail: [],
      },
    ]);
  });

  it("show the key and the address before adding a repository", () => {
    expect(
      repoLines(
        {
          what: "addrepo",
          name: "tailscale",
          uri: "https://pkgs.tailscale.com/stable/debian",
          suites: ["bookworm"],
          components: ["main"],
          file: "/etc/apt/sources.list.d/tailscale.sources",
          key: {
            fingerprint: "2596a99eaab33821893c0a79458ca832957f5868",
            user: "Tailscale Inc. (Package repository signing key)",
          },
          answers: true,
          packages: ["tailscale", "tailscale-archive-keyring"],
          count: 2,
          refused: null,
        },
        "Debian 12 bookworm",
      ),
    ).toEqual([
      {
        mark: "✓",
        title:
          "Key fetched over HTTPS · Tailscale Inc. (Package repository signing key)",
        detail: [
          "2596 A99E AAB3 3821 893C 0A79 458C A832 957F 5868",
          "Compare it with the one on the vendor's site before you add it.",
        ],
      },
      {
        mark: "✓",
        title:
          "The address answers for bookworm · 2 packages: tailscale, tailscale-archive-keyring",
        detail: [],
      },
      {
        mark: "+",
        title: "Writes /etc/apt/sources.list.d/tailscale.sources and its key",
        detail: [
          "The key is trusted for this repository only, never for Debian's own packages.",
        ],
      },
    ]);
  });

  it("say what happened when it is done", () => {
    const upgraded = action({
      output: JSON.stringify({
        upgraded: ["docker-ce", "openssl", "tailscale"],
        moved: [],
        added: ["docker-ce-rootless-extras"],
        removed: [],
        took: 72,
        waited: 41,
        holder: "unattended-upgrades",
        repaired: false,
        kept: [],
        restarted: ["docker.service"],
        old: ["sshd.service"],
      }),
    });
    expect(
      finishedLines(upgraded, {
        nodeName: "vps-2",
        stacks: [{ project: "db", running: 1, total: 1 }],
      }),
    ).toEqual([
      {
        mark: "✓",
        title: "Waited 41s for unattended-upgrades to finish",
        detail: [],
      },
      { mark: "✓", title: "Upgraded 3, added 1", detail: ["1m 12s"] },
      {
        mark: "✓",
        title: "Docker restarted · db is running again",
        detail: [],
      },
      {
        mark: "!",
        title: "Restart Needed",
        detail: [
          "sshd still uses old libraries. Restart Server, or restart just sshd from Services.",
        ],
      },
    ]);
    const tailscale = action({
      action: "install",
      name: "tailscale",
      output: JSON.stringify({
        upgraded: [],
        moved: [],
        added: ["tailscale", "tailscale-archive-keyring"],
        removed: [],
        took: 14,
        waited: 0,
        repaired: false,
        kept: [],
      }),
    });
    expect(
      finishedLines(tailscale, {
        nodeName: "vps-2",
        tailscale: {
          state: "needs-login",
          addresses: [],
          name: null,
          keyExpiry: null,
        },
      }),
    ).toEqual([
      {
        mark: "✓",
        title: "Installed 2 packages",
        detail: ["tailscale, tailscale-archive-keyring", "14s"],
      },
      {
        mark: "✓",
        title: "tailscaled is running, and starts at every boot",
        detail: [],
      },
      {
        mark: "!",
        title: "vps-2 is not on your tailnet yet",
        detail: ["Sign it in from here. No terminal needed."],
      },
    ]);
    const failed = action({
      action: "install",
      name: "nginx",
      status: "failed",
      output: JSON.stringify({
        upgraded: [],
        moved: [],
        added: ["nginx", "nginx-common"],
        removed: [],
        took: 9,
        waited: 0,
        repaired: true,
        kept: [],
        failed: "E: Sub-process /usr/bin/dpkg returned an error code (1)",
      }),
    });
    expect(finishedLines(failed, { nodeName: "vps-2" })).toEqual([
      {
        mark: "✓",
        title: "Finished an earlier apt run that was cut off",
        detail: [],
      },
      {
        mark: "✕",
        title: "E: Sub-process /usr/bin/dpkg returned an error code (1)",
        detail: [],
      },
      {
        mark: "✓",
        title: "Removed what it had added: nginx and nginx-common",
        detail: [],
      },
    ]);
  });

  it("time a job in seconds, then minutes and seconds", () => {
    expect(tookText(14)).toBe("14s");
    expect(tookText(72)).toBe("1m 12s");
    expect(tookText(120)).toBe("2m");
  });
});

describe("a vendor's instructions", () => {
  it("give only addresses", () => {
    expect(
      parseVendorPaste(
        "curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null\ncurl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list",
      ),
    ).toEqual({
      name: "tailscale",
      release: "bookworm",
      components: null,
      uri: "https://pkgs.tailscale.com/stable/debian",
      key: "https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg",
      list: "https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list",
    });
    expect(
      parseVendorPaste(
        'sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc\necho "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null',
      ),
    ).toEqual({
      name: "docker",
      release: null,
      components: "stable",
      uri: "https://download.docker.com/linux/debian",
      key: "https://download.docker.com/linux/debian/gpg",
      list: null,
    });
    expect(
      parseVendorPaste(
        "deb https://deb.nodesource.com/node_20.x nodistro main",
      ),
    ).toEqual({
      name: "nodesource",
      release: "nodistro",
      components: "main",
      uri: "https://deb.nodesource.com/node_20.x",
      key: null,
      list: null,
    });
    expect(
      parseVendorPaste("rm -rf / ; deb http://example.com stable main"),
    ).toEqual({
      name: null,
      release: null,
      components: null,
      uri: null,
      key: null,
      list: null,
    });
  });
});

describe("History and the hourglass", () => {
  it("say what was done in the imperative", () => {
    const texts = [
      action({ action: "install", name: "nginx" }),
      action({
        output: JSON.stringify({
          upgraded: Array.from({ length: 13 }, (_, i) => `p${i}`),
          added: ["x"],
          moved: [],
          removed: [],
          took: 1,
          waited: 0,
          repaired: false,
          kept: [],
        }),
      }),
      action({ action: "hold", name: "nodejs", output: "hold nodejs 20.18.0" }),
      action({ action: "unhold", name: "nodejs" }),
      action({ action: "addrepo", name: "tailscale" }),
      action({ action: "droprepo", name: "tailscale" }),
      action({ action: "remove", name: "tailscale" }),
      action({ action: "purge", name: "tailscale" }),
      action({ action: "refresh" }),
      action({ status: "failed" }),
    ].map((entry) => packageText(entry));
    expect(texts).toEqual([
      "Install nginx",
      "Upgrade 14 packages",
      "Hold nodejs at 20.18.0",
      "Release the hold on nodejs",
      "Add the tailscale repository",
      "Remove the tailscale repository",
      "Remove tailscale",
      "Remove tailscale with its settings",
      "Check for updates",
      "Upgrade packages",
    ]);
    const signin = action({
      kind: "host",
      name: "tailscale",
      action: "signin",
    });
    expect(historyText(signin, [], "vps-2")).toBe("Sign in vps-2 to Tailscale");
    expect(
      actionLine(signin, { nodeName: "vps-2", showServer: true }).server,
    ).toBeNull();
    expect(
      actionLine(action({ action: "install", name: "nginx" }), {
        nodeName: "vps-2",
        showServer: true,
      }),
    ).toMatchObject({
      text: "Install nginx",
      server: "vps-2",
    });
  });

  it("show a long job's step", () => {
    expect(
      runningJob(
        action({
          status: "sent",
          progress: {
            at: ago(1_000),
            done: 6,
            total: 14,
            line: "unpacking docker-ce",
          },
        }),
        "vps-2",
        NOW,
      ),
    ).toEqual({
      title: "Upgrading packages on vps-2 · 41s",
      step: "6 of 14 · unpacking docker-ce",
    });
    expect(
      runningJob(action({ status: "sent" }), "vps-2", NOW).step,
    ).toBeNull();
  });

  it("open an upgrade to each package from and to, then what it restarted", () => {
    const upgraded = action({
      output: JSON.stringify({
        upgraded: ["openssl"],
        moved: [{ name: "openssl", from: "3.0.13-1", to: "3.0.14-1" }],
        added: ["linux-image-6.1.0-27"],
        removed: [],
        took: 30,
        waited: 0,
        repaired: false,
        kept: [],
        old: ["sshd.service"],
      }),
    });
    expect(historyLines(upgraded, "vps-2")).toEqual([
      { mark: "↑", title: "openssl 3.0.13-1 → 3.0.14-1", detail: [] },
      { mark: "+", title: "linux-image-6.1.0-27", detail: [] },
      { mark: "✓", title: "Upgraded 1, added 1", detail: ["30s"] },
      {
        mark: "!",
        title: "Restart Needed",
        detail: [
          "sshd still uses old libraries. Restart Server, or restart just sshd from Services.",
        ],
      },
    ]);
    expect(
      historyLines(
        action({
          action: "hold",
          name: "nodejs",
          output: "hold nodejs 20.18.0",
        }),
        "vps-2",
      ),
    ).toBeNull();
  });

  it("try a failed job again in the dialog that made it, with the same package", () => {
    expect(retryDialog(action({ action: "upgrade" }))).toEqual({
      kind: "upgrade",
    });
    expect(retryDialog(action({ action: "install", name: "nginx" }))).toEqual({
      kind: "install",
      name: "nginx",
    });
    expect(retryDialog(action({ action: "purge", name: "tailscale" }))).toEqual(
      { kind: "remove", name: "tailscale" },
    );
  });

  it("tell the stacks' state from what the job recorded when Docker restarted", () => {
    const outcome = {
      upgraded: ["docker-ce"],
      moved: [{ name: "docker-ce", from: "27.3.1", to: "27.4.0" }],
      added: [],
      removed: [],
      took: 40,
      waited: 0,
      repaired: false,
      kept: [],
      restarted: ["docker.service"],
    };
    const recorded = action({
      output: JSON.stringify({
        ...outcome,
        stacks: [
          { project: "db", running: 1, total: 1 },
          { project: "web", running: 0, total: 1 },
        ],
      }),
    });
    expect(historyLines(recorded, "vps-2")).toContainEqual({
      mark: "!",
      title: "Docker restarted · web is not running yet",
      detail: [],
    });
    expect(
      historyLines(
        action({
          output: JSON.stringify({
            ...outcome,
            stacks: [{ project: "db", running: 1, total: 1 }],
          }),
        }),
        "vps-2",
      ),
    ).toContainEqual({
      mark: "✓",
      title: "Docker restarted · db is running again",
      detail: [],
    });
  });

  it("say what a failed upgrade changed and show apt's last lines", () => {
    const failed = action({
      status: "failed",
      output: JSON.stringify({
        upgraded: [],
        moved: [],
        added: [],
        removed: [],
        took: 4,
        waited: 0,
        repaired: false,
        kept: [],
        failed: "Could not resolve 'deb.debian.org'",
        tail: [
          "Err:1 http://deb.debian.org/debian bookworm InRelease",
          "E: Could not resolve 'deb.debian.org'",
        ],
      }),
    });
    expect(changedLines(outcomeOf(failed)!)).toEqual([
      {
        mark: "·",
        title: "Nothing changed: apt stopped before unpacking anything.",
        detail: [],
      },
    ]);
    expect(aptOutput(failed)).toBe(
      "Err:1 http://deb.debian.org/debian bookworm InRelease\nE: Could not resolve 'deb.debian.org'",
    );
    expect(actionLine(failed).failure).toBe(
      "Could not resolve 'deb.debian.org'",
    );
    const refused = action({
      action: "addrepo",
      name: "tailscale",
      status: "failed",
      output: "the key does not match",
    });
    expect(aptOutput(refused)).toBe("the key does not match");
    expect(actionLine(refused).failure).toBe("the key does not match");
  });
});

describe("the installed list's menu", () => {
  const entry = report.packages[0]!;

  it("says which feature removes what Krynodes installed", () => {
    expect(packageMenu({ ...entry, feature: "docker" })).toEqual({
      note: "Krynodes installed it for Docker",
      items: ["hold"],
    });
    expect(packageMenu({ ...entry, feature: "network" })).toEqual({
      note: "Krynodes installed it for the private network; it goes when the server leaves",
      items: ["hold"],
    });
    expect(packageMenu({ ...entry, feature: "fail2ban" })).toEqual({
      note: "Turn off Block Repeated Login Failures to remove it",
      items: ["hold"],
    });
  });

  it("offers a hold or its release, and Remove", () => {
    expect(packageMenu(report.packages[2]!)).toEqual({
      note: null,
      items: ["hold", "remove"],
    });
    expect(packageMenu(report.packages[3]!).items).toEqual([
      "unhold",
      "remove",
    ]);
  });

  it("never offers to remove openssh-server", () => {
    expect(
      packageMenu({ ...entry, name: "openssh-server", feature: null }).items,
    ).toEqual(["hold"]);
  });
});

describe("Search", () => {
  const nodes = [
    {
      ...node,
      updates: {
        waiting: 3,
        security: 1,
        held: 0,
        checkedAt: null,
        restart: null,
      },
    },
    {
      ...node,
      id: "22222222-2222-4222-8222-222222222222",
      name: "pivox",
      updates: null,
    },
  ];
  const servers = [
    { nodeId: node.id, names: ["nginx", "nginx-common", "htop"] },
    { nodeId: "33333333-3333-4333-8333-333333333333", names: ["nginx"] },
  ];

  it("opens Packages on the servers that use apt", () => {
    expect(packageCommands(nodes, servers, "")).toEqual([
      {
        key: `packages|${node.id}`,
        value: "packages updates apt vps-2",
        label: "Packages · vps-2",
        to: `/nodes/${node.id}/packages`,
      },
    ]);
  });

  it("finds an installed package once two letters are typed", () => {
    expect(
      packageCommands(nodes, servers, " NGI").map((entry) => entry.label),
    ).toEqual(["Packages · vps-2", "nginx · vps-2", "nginx-common · vps-2"]);
    expect(packageCommands(nodes, servers, "ngi")[1]!.to).toBe(
      `/nodes/${node.id}/packages?q=nginx&show=all`,
    );
    expect(packageCommands(nodes, servers, "n")).toHaveLength(1);
  });
});

describe("jobs on the page", () => {
  it("keeps the long jobs that are still going, never a search", () => {
    const actions = [
      action({ id: "1", status: "sent" }),
      action({ id: "2", status: "queued", action: "find" }),
      action({ id: "3", status: "done" }),
      action({
        id: "4",
        status: "sent",
        kind: "host",
        name: "tailscale",
        action: "signin",
      }),
      action({ id: "5", status: "sent", nodeId: "other" }),
      action({ id: "6", status: "sent", kind: "docker", action: "restart" }),
    ];
    expect(runningPackages(actions, node.id).map((entry) => entry.id)).toEqual([
      "1",
      "4",
    ]);
  });
});
describe("a source's own name", () => {
  it("is its file's name, the one Remove sends", () => {
    expect(repoName("/etc/apt/sources.list.d/tailscale.sources")).toBe(
      "tailscale",
    );
    expect(repoName("/etc/apt/sources.list.d/docker.list")).toBe("docker");
  });
});
describe("Sign In", () => {
  const waiting: TailscaleReport = {
    ...running,
    state: "needs-login",
    keyExpiry: null,
  };

  it("is approved once tailscaled runs on a key it did not have before", () => {
    expect(signedIn(waiting, waiting)).toBe(false);
    expect(signedIn(waiting, running)).toBe(true);
    expect(signedIn(waiting, { ...running, keyExpiry: null })).toBe(true);
    expect(signedIn(running, running)).toBe(false);
    expect(
      signedIn(running, { ...running, keyExpiry: "2027-10-26T10:00:00.000Z" }),
    ).toBe(true);
    expect(signedIn(running, null)).toBe(false);
  });

  it("names what signing in leaves alone", () => {
    expect(signInRows("vps-2", false)).toEqual([
      "vps-2 keeps its own DNS",
      "Tailscale SSH stays off",
    ]);
    expect(signInRows("vps-2", true)).toEqual([
      "vps-2 keeps its other Tailscale settings",
    ]);
  });

  it("says where it is on the tailnet and when its key ends", () => {
    expect(signedInLines(running, "vps-2")).toEqual([
      {
        mark: "✓",
        title: "vps-2 is on your tailnet",
        detail: ["100.101.7.12 · vps-2.tail4d2a.ts.net"],
      },
      {
        mark: "·",
        title: "Its Tailscale key expires on 24 Apr 2027",
        detail: [
          "Krynodes tells you 14 days before. Or turn off key expiry for vps-2 in Tailscale's admin console.",
        ],
      },
    ]);
    expect(signedInLines({ ...running, keyExpiry: null }, "vps-2")[1]).toEqual({
      mark: "·",
      title: "Its Tailscale key does not expire",
      detail: [],
    });
  });
});
describe("a finished job", () => {
  const context = { nodeName: "vps-2" };

  it("says what a repository change or a check did", () => {
    expect(
      jobLines(
        action({
          action: "addrepo",
          name: "tailscale",
          output: '{"file":"/etc/apt/sources.list.d/tailscale.sources"}',
        }),
        context,
      ),
    ).toEqual([
      {
        mark: "✓",
        title: "Added the tailscale repository",
        detail: ["/etc/apt/sources.list.d/tailscale.sources"],
      },
    ]);
    expect(
      jobLines(
        action({
          action: "droprepo",
          name: "tailscale",
          output: "removed tailscale",
        }),
        context,
      ),
    ).toEqual([
      { mark: "✓", title: "Removed the tailscale repository", detail: [] },
    ]);
    expect(
      jobLines(action({ action: "refresh", output: "checked" }), context),
    ).toEqual([{ mark: "✓", title: "Checked for updates", detail: [] }]);
    expect(
      jobLines(
        action({
          action: "droprepo",
          status: "failed",
          output: "docker-ce still comes from it",
        }),
        context,
      ),
    ).toEqual([
      { mark: "✕", title: "docker-ce still comes from it", detail: [] },
    ]);
    expect(jobLines(action({ status: "sent" }), context)).toEqual([]);
  });

  it("hands an install, an upgrade or a removal to their own lines", () => {
    const done = action({
      output: JSON.stringify({
        upgraded: ["openssl"],
        moved: [],
        added: [],
        removed: [],
        took: 12,
        waited: 0,
        repaired: false,
        kept: [],
      }),
    });
    expect(jobLines(done, context)).toEqual(finishedLines(done, context));
  });
});

describe("Fleet", () => {
  const summary = {
    waiting: 3,
    security: 2,
    held: 0,
    checkedAt: null,
    restart: {
      since: ago(60_000),
      running: "6.1.0-26",
      newest: "6.1.0-27",
      file: true,
      services: [],
    },
  };
  const off = {
    recipes: [],
    rebootHour: null,
    findings: [{ id: "updates-off", severity: "warning", detail: "" }],
  } as unknown as SecurityReport;
  const on = {
    recipes: ["reboot-window", "security-updates"],
    rebootHour: 20,
    findings: [],
  } as unknown as SecurityReport;

  it("raises what nothing will fix on its own", () => {
    expect(
      packageAttention(
        { ...node, updates: summary, tailscale: null },
        off,
        NOW,
      ),
    ).toEqual({
      reasons: ["Restart Needed", "2 security updates waiting"],
      notes: [],
    });
  });

  it("leaves a grey line for what fixes itself", () => {
    expect(
      packageAttention(
        { ...node, updates: summary, tailscale: null },
        on,
        NOW,
        -420,
      ),
    ).toEqual({ reasons: [], notes: [restartLine(on, -420)] });
    expect(restartLine(on, -420)).toBe(
      "Restarts at 03:00 by Restart When Needed",
    );
  });

  it("raises an expired Tailscale key and notes one about to expire", () => {
    expect(
      packageAttention(
        {
          ...node,
          updates: null,
          tailscale: { ...running, keyExpiry: ago(DAY) },
        },
        on,
        NOW,
      ),
    ).toEqual({ reasons: ["Tailscale key expired"], notes: [] });
    expect(
      packageAttention(
        {
          ...node,
          updates: null,
          tailscale: { ...running, keyExpiry: ahead(12 * DAY) },
        },
        on,
        NOW,
      ),
    ).toEqual({ reasons: [], notes: ["Tailscale key expires in 12 days"] });
    expect(
      packageAttention(
        {
          ...node,
          updates: null,
          tailscale: {
            ...running,
            keyExpiry: ahead(12 * DAY),
            tags: ["tag:kry"],
          },
        },
        on,
        NOW,
      ),
    ).toEqual({ reasons: [], notes: [] });
  });

  it("says on the card what a package job is doing", () => {
    expect(
      busyText(
        action({
          status: "sent",
          progress: { at: ago(1_000), done: 6, total: 14, line: "unpacking" },
        }),
      ),
    ).toBe("Upgrading packages · 6 of 14");
    expect(
      busyText(action({ status: "sent", action: "install", name: "nginx" })),
    ).toBe("Installing nginx");
    expect(
      busyText(action({ kind: "host", name: "tailscale", action: "signin" })),
    ).toBe("Signing in to Tailscale");
    expect(busyText(action({ kind: "docker", action: "restart" }))).toBeNull();
  });
});
