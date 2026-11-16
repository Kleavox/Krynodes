import { codeOf, releaseText } from "@krynodes/protocol";
import { describe, expect, it } from "vitest";

import type {
  ActionRecord,
  NodeWarning,
  QuarantineRecord,
  QuarantineView,
} from "../types";
import { historyText } from "./history";
import type { VaultNode } from "./vault";
import {
  acceptsWarning,
  actionsFor,
  changeThese,
  planWithout,
  fleetQuarantine,
  QUARANTINE_INTRO,
  releaseInputs,
  resharing,
  quarantineCard,
  releaseCode,
  releaseCodeProblem,
  releaseSteps,
  REPORTED,
  settingsRows,
  stoppedRow,
  warningStrip,
  whatHappened,
} from "./quarantine";

const NOW = Date.parse("2026-10-27T14:10:00Z");
const V1 = "11111111-1111-4111-8111-111111111111";
const V2 = "22222222-2222-4222-8222-222222222222";
const V3 = "33333333-3333-4333-8333-333333333333";

const warning = (
  kind: string,
  detail: Record<string, string>,
  cutAt: string | null = "2026-10-27T14:19:00Z",
): NodeWarning => ({
  id: "w1",
  kind,
  detail,
  at: "2026-10-27T14:04:00Z",
  cutAt,
});

describe("the warning strip", () => {
  it("says what is new, when, and when the server is cut off", () => {
    expect(
      warningStrip(
        warning("ssh-key", {
          user: "root",
          file: "/root/.ssh/authorized_keys",
          key: "ED25519 SHA256:Qm7c deploy@unknown",
        }),
        "vps-1",
        NOW,
      ),
    ).toEqual({
      title: "New SSH key for root, not added through Krynodes · 21:04",
      detail: "ED25519 SHA256:Qm7c deploy@unknown",
      cutoff:
        "vps-1 is cut off from the network at 21:19 unless you say it was you.",
    });
  });

  it("words every medium signal, with -- where the server said nothing", () => {
    const strip = (kind: string, detail: Record<string, string>) => {
      const { title, detail: line } = warningStrip(
        warning(kind, detail),
        "vps-1",
        NOW,
      );
      return [title, line];
    };
    expect(
      strip("ssh-login", {
        user: "root",
        from: "203.0.113.9",
        key: "ED25519 SHA256:x",
      }),
    ).toEqual([
      "root signed in with a key not from Krynodes · 21:04",
      "ED25519 SHA256:x · from 203.0.113.9",
    ]);
    expect(strip("user", { user: "deploy" })).toEqual([
      "New user deploy, not added through Krynodes · 21:04",
      null,
    ]);
    expect(strip("sudo", { rule: "/etc/sudoers.d/90-x" })).toEqual([
      "New sudo rule, not added through Krynodes · 21:04",
      "/etc/sudoers.d/90-x",
    ]);
    expect(strip("port", { port: "4444/tcp" })).toEqual([
      "4444/tcp opened on a public address, not through Krynodes · 21:04",
      "Process --",
    ]);
    expect(
      strip("port", { port: "443/tcp", process: "python3.11", was: "nginx" }),
    ).toEqual([
      "443/tcp now answered by python3.11 instead of nginx, not through Krynodes · 21:04",
      "Process python3.11",
    ]);
    expect(strip("rule", { chain: "KRY-REACH", rule: "-j DROP" })).toEqual([
      "Krynodes' firewall rule was removed, and put back · 21:04",
      "KRY-REACH · -j DROP",
    ]);
    expect(strip("firewall", { rule: "allow 9999/tcp" })).toEqual([
      "Firewall rule added, not through Krynodes · 21:04",
      "allow 9999/tcp",
    ]);
    expect(
      strip("confinement", {
        system: "selinux",
        program: "nginx",
        type: "httpd_t",
        wanted: "read shadow",
        item: "nginx httpd_t",
      }),
    ).toEqual(["SELinux denied nginx · 21:04", "httpd_t · read shadow"]);
    expect(strip("confinement", { system: "apparmor" })).toEqual([
      "AppArmor denied -- · 21:04",
      "-- · --",
    ]);
    expect(
      strip("quiet", {
        lastReport: "2026-10-27T13:58:00Z",
        seenBy: "vps-2, vps-3",
      }),
    ).toEqual([
      "The agent went quiet while the server is up · 21:04",
      "Last report 20:58 · seen by vps-2, vps-3",
    ]);
    expect(strip("user", {})).toEqual([
      "New user --, not added through Krynodes · 21:04",
      null,
    ]);
  });

  it("says when nothing cuts the server off, or that it is being cut off", () => {
    expect(
      warningStrip(warning("user", { user: "x" }, null), "vps-1", NOW).cutoff,
    ).toBe(
      "Warn Only is set, so vps-1 stays on the network until you cut it off.",
    );
    expect(
      warningStrip(
        warning("user", { user: "x" }, "2026-10-27T14:09:00Z"),
        "vps-1",
        NOW,
      ).cutoff,
    ).toBe("vps-1 is being cut off from the network.");
  });
});

const record = (extra: Partial<QuarantineRecord> = {}): QuarantineRecord => ({
  id: "q1",
  why: "vps-2 and vps-3 saw it knock on 41 closed ports in one minute",
  at: "2026-10-27T14:18:01Z",
  releasedAt: null,
  releasedBy: null,
  address: "10.88.0.1",
  knocks: [
    { reporter: "vps-2", at: "2026-10-27T14:17:40Z", count: 23 },
    { reporter: "vps-3", at: "2026-10-27T14:17:52Z", count: 18 },
  ],
  steps: [
    {
      nodeId: V1,
      nodeName: "vps-1",
      action: "lockdown",
      status: "done",
      finishedAt: "2026-10-27T14:18:05Z",
    },
    {
      nodeId: V2,
      nodeName: "vps-2",
      action: "drop",
      status: "done",
      finishedAt: "2026-10-27T14:18:02Z",
    },
    {
      nodeId: V3,
      nodeName: "vps-3",
      action: "drop",
      status: "done",
      finishedAt: "2026-10-27T14:18:02Z",
    },
  ],
  ...extra,
});

describe("a quarantined server's page", () => {
  it("draws the red card and marks the report as the server's own", () => {
    expect(
      quarantineCard(
        { at: "2026-10-27T14:18:01Z", why: record().why },
        "vps-1",
        NOW,
      ),
    ).toEqual({
      chip: "Quarantined",
      title:
        "Cut off from the network at 21:18 · vps-2 and vps-3 saw it knock on 41 closed ports in one minute",
      body: "Every other server dropped vps-1 and blocks its WireGuard key for good. Krynodes sends it nothing and refuses every action except reading.",
      next: "Really broken into? Reinstall it and enroll it again. A false alarm? Release it from the server itself.",
    });
    expect(REPORTED).toBe("Reported by the server itself, may not be true");
  });

  it("tells What Happened to the second, with who dropped it and the Lock Down", () => {
    expect(whatHappened(record(), NOW)).toEqual([
      {
        time: "21:17:40",
        lead: null,
        text: "vps-2 saw 10.88.0.1 knock on 23 closed ports",
      },
      {
        time: "21:17:52",
        lead: null,
        text: "vps-3 saw 10.88.0.1 knock on 18 closed ports",
      },
      { time: "21:18:01", lead: "Quarantined", text: "two servers agree" },
      {
        time: "21:18:02",
        lead: null,
        text: "vps-2 ✓ dropped it · vps-3 ✓ dropped it",
      },
      {
        time: "21:18:05",
        lead: null,
        text: "Lock Down on vps-1 ✓ reported by the server itself",
      },
    ]);
  });

  it("says which blocks still wait or failed, and stays silent on an old Tailscale block", () => {
    const lines = whatHappened(
      record({
        why: "Nobody said the new SSH key for root was theirs within 15 minutes",
        knocks: [],
        steps: [
          {
            nodeId: V1,
            nodeName: "vps-1",
            action: "lockdown",
            status: "sent",
            finishedAt: null,
          },
          {
            nodeId: V2,
            nodeName: "vps-2",
            action: "drop",
            status: "done",
            finishedAt: "2026-10-27T14:18:02Z",
          },
          {
            nodeId: V3,
            nodeName: "vps-3",
            action: "drop",
            status: "queued",
            finishedAt: null,
          },
          {
            nodeId: V2,
            nodeName: "vps-2",
            action: "block",
            status: "done",
            finishedAt: "2026-10-27T14:18:03Z",
          },
          {
            nodeId: V3,
            nodeName: "vps-3",
            action: "block",
            status: "failed",
            finishedAt: "2026-10-27T14:18:04Z",
          },
        ],
      }),
      NOW,
    );
    expect(lines).toEqual([
      {
        time: "21:18:01",
        lead: "Quarantined",
        text: "nobody said the new SSH key for root was theirs within 15 minutes",
      },
      {
        time: "21:18:01",
        lead: null,
        text: "Lock Down on vps-1 · waiting for it to report",
      },
      {
        time: "21:18:02",
        lead: null,
        text: "vps-2 ✓ dropped it · vps-3 drops it when it reports",
      },
    ]);
    expect(
      whatHappened(record({ knocks: [], why: "vps-2 saw it knock" }), NOW)[0],
    ).toEqual({
      time: "21:18:01",
      lead: "Quarantined",
      text: "vps-2 saw it knock",
    });
    expect(
      whatHappened(record(), Date.parse("2026-10-29T03:00:00Z"))[0]!.time,
    ).toBe("27 Oct 21:17:40");
  });

  it("lists what to change, by name, without the names of secrets it never had", () => {
    const view: QuarantineView = {
      quarantine: record(),
      release: null,
      stopped: [],
      changeThese: {
        stacks: ["app", "worker"],
        vault: { set: "s1", holders: 3 },
        webAddresses: [
          { hostname: "app.example.org", project: "app" },
          { hostname: "api.example.org", project: "app" },
        ],
        trusted: [
          { nodeId: V2, nodeName: "vps-2", project: "db", port: "5432/tcp" },
        ],
      },
    };
    expect(changeThese(view, "vps-1")).toEqual({
      title: "Change These · vps-1 could read or reach them",
      rows: [
        {
          id: "stacks",
          title: "Secrets of app and worker",
          tag: null,
          note: "Secrets sent to stacks on vps-1. Each compose file names them.",
          action: null,
        },
        {
          id: `trusted:${V2}:db:5432/tcp`,
          title: "vps-2 · 5432/tcp",
          tag: "db",
          note: "Trusted vps-1. Change the password vps-1 used to sign in.",
          action: null,
        },
        {
          id: "vault",
          title: "Cloudflare token",
          tag: "vps-1 held 1 of 3 pieces",
          note: "One piece alone opens nothing. Reshare so the old piece is worthless.",
          action: { kind: "reshare", label: "Reshare Without It" },
        },
        {
          id: "web",
          title: "app.example.org, api.example.org",
          tag: null,
          note: "Still points at vps-1's tunnel",
          action: { kind: "unexpose", label: "Remove Web Addresses" },
        },
      ],
    });
    expect(
      changeThese(
        {
          ...view,
          quarantine: record(),
          changeThese: {
            stacks: [],
            vault: null,
            webAddresses: [],
            trusted: [],
          },
        },
        "vps-1",
      ).rows,
    ).toEqual([
      {
        id: "none",
        title: "Nothing Krynodes knows of",
        tag: null,
        note: null,
        action: null,
      },
    ]);
  });

  it("keeps only Refresh Services, Release Server, Remove from Network and Delete Node", () => {
    const quarantine = { at: "2026-10-27T14:18:01Z", why: "why" };
    expect(
      actionsFor({
        quarantine,
        network: { state: "in", address: "10.88.0.1", port: 51820 },
      }),
    ).toEqual([
      "Refresh Services",
      "Release Server",
      "Remove from Network",
      "Delete Node",
    ]);
    expect(actionsFor({ quarantine, network: null })).toEqual([
      "Refresh Services",
      "Release Server",
      "Delete Node",
    ]);
    expect(actionsFor({ quarantine: null })).toBeNull();
  });
});

describe("what It Was Me and the reshare send", () => {
  it("asks the agent to accept only what it can keep as a starting point", () => {
    expect(
      [
        "ssh-key",
        "ssh-login",
        "user",
        "sudo",
        "port",
        "firewall",
        "confinement",
        "rule",
        "quiet",
      ].map(acceptsWarning),
    ).toEqual([true, true, true, true, true, true, true, false, false]);
  });

  it("reshares without the quarantined server: it neither assembles, releases, holds nor forgets", () => {
    const node = (id: string, name: string, holders = 3): VaultNode => ({
      id,
      name,
      sealKey: `seal-${name}`,
      vault: { set: "s1", holders },
      reachable: true,
      online: true,
    });
    const plan = planWithout(
      [node(V1, "vps-1"), node(V2, "vps-2"), node(V3, "vps-3")],
      V1,
      "s1",
    );
    expect(plan).toMatchObject({ ok: true, needed: true });
    if (!plan.ok || !plan.needed) return;
    expect([plan.assembler, plan.releaser]).not.toContain(V1);
    expect(plan.holders.map((holder) => holder.nodeId)).toEqual([V2, V3]);
    expect(plan.forgets).not.toContain(V1);
  });
});

describe("Release", () => {
  const pending = {
    key: "a2V5",
    signer: "c2lnbmVy",
    seal: "c2VhbA",
    token: "a".repeat(64),
    expires: "2026-10-27T14:20:00.000Z",
  };

  it("names the three steps", () => {
    expect(releaseSteps("vps-1")).toEqual({
      title: "Release vps-1",
      intro:
        "This trusts vps-1 again. The code shows you were on the server; it does not show the server is clean.",
      run: "On vps-1, run",
      command: "sudo kry release-code",
      type: "Type the code it shows",
      lasts: "works for 10 minutes",
      keys: "vps-1 makes new keys: WireGuard, sealing and its sign-in to Krynodes. The old ones stay blocked, and secrets are sealed to the new ones.",
    });
  });

  it("checks the code against the keys the server reported, before any fingerprint", async () => {
    const code = codeOf(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(releaseText(pending)),
        ),
      ),
    );
    expect(await releaseCode(pending)).toBe(code);
    const typed = code.replace("-", " ").toLowerCase();
    expect(await releaseCodeProblem(typed, pending, "vps-1", NOW)).toEqual({
      code,
      problem: null,
    });
    expect(
      (await releaseCodeProblem("AAAAA-AAAAA", pending, "vps-1", NOW)).problem,
    ).toBe("That is not the code vps-1 showed. Type it again.");
    expect(
      (
        await releaseCodeProblem(
          code,
          pending,
          "vps-1",
          Date.parse(pending.expires),
        )
      ).problem,
    ).toBe("That code has ended. Run sudo kry release-code on vps-1 again.");
    expect((await releaseCodeProblem(code, null, "vps-1", NOW)).problem).toBe(
      "Run sudo kry release-code on vps-1 first.",
    );
    expect(
      (await releaseCodeProblem("7K43", pending, "vps-1", NOW)).problem,
    ).toBe("The code has ten letters and digits, such as 7K43Q-MZ2PA.");
  });
});

describe("a stopped stack", () => {
  it("says who stopped it, where it tried to go, and that the server is still trusted", () => {
    const names = { "10.88.0.2": "vps-2", "10.88.0.3": "vps-3" };
    expect(
      stoppedRow(
        {
          project: "app",
          at: "2026-10-27T14:04:00Z",
          tried: [
            "10.88.0.3:6379/tcp",
            "10.88.0.3:22/tcp",
            "10.88.0.2:22/tcp",
            "10.88.0.2:2375/tcp",
          ],
          count: 14,
        },
        "vps-1",
        names,
        NOW,
      ),
    ).toEqual({
      title:
        "Stopped by Krynodes at 21:04: a container tried 14 places it was not given",
      places: "vps-3:6379/tcp, vps-3:22/tcp, vps-2:22/tcp, vps-2:2375/tcp …",
      note: "vps-1 is still trusted. Only this stack was stopped, and it stays stopped after a reboot. Change its secrets before you start it again.",
    });
    expect(
      stoppedRow(
        {
          project: "app",
          at: "2026-10-27T14:04:00Z",
          tried: ["10.88.0.9:80/tcp"],
          count: 0,
        },
        "vps-1",
        names,
        NOW,
      ),
    ).toMatchObject({
      title:
        "Stopped by Krynodes at 21:04: a container tried 1 place it was not given",
      places: "10.88.0.9:80/tcp",
    });
  });

  it("says SELinux or AppArmor denied it, and what was wanted", () => {
    expect(
      stoppedRow(
        {
          project: "panel",
          at: "2026-10-27T14:04:00Z",
          tried: ["read shadow"],
          count: 1,
          why: "confinement",
        },
        "server-1",
        {},
        NOW,
      ),
    ).toEqual({
      title:
        "Stopped by Krynodes at 21:04: SELinux or AppArmor denied one of its containers",
      places: "read shadow",
      note: "server-1 is still trusted. Only this stack was stopped, and it stays stopped after a reboot. Change its secrets before you start it again.",
    });
  });
});

describe("Settings → Quarantine", () => {
  it("has four rows with their defaults and choices", () => {
    expect(QUARANTINE_INTRO).toBe(
      "What Krynodes does on its own when a server looks broken into. It only ever takes access away; giving it back always asks for your passkey.",
    );
    const rows = settingsRows(true);
    expect(rows.map((row) => [row.key, row.title, row.later])).toEqual([
      ["cutoff", "Cut off after a warning", null],
      ["scan", "Counts as a Scan", null],
      ["agree", "Cut off from every server", null],
      ["stop", "Stop a stack that knocks", null],
    ]);
    expect(rows.map((row) => row.note)).toEqual([
      "New SSH keys, users or sudo rules, ports opened outside Krynodes, an agent that goes quiet while the server is up",
      "Closed ports or servers knocked on in one minute. One wrong port knocked again and again is a setting mistake, and only sends a warning.",
      "A server that is knocked on always drops the knocker for itself",
      "A Contained container that tries places it was not given",
    ]);
    expect(
      rows.map((row) => row.choices.map((choice) => choice.label)),
    ).toEqual([
      [
        "After 5 Minutes",
        "After 15 Minutes",
        "After 30 Minutes",
        "After 60 Minutes",
        "Warn Only",
      ],
      ["5 or More", "10 or More", "20 or More"],
      ["When 1 Server Sees It", "When 2 Servers Agree", "When 3 Servers Agree"],
      ["At Once", "Warn Only"],
    ]);
    expect(rows[0]!.choices.at(-1)!.value).toBeNull();
    expect(rows[3]!.choices.map((choice) => choice.value)).toEqual([
      true,
      false,
    ]);
  });

  it("says the knock rows apply once servers share a network", () => {
    expect(settingsRows(false).map((row) => row.later)).toEqual([
      null,
      "Applies once servers share a network.",
      "Applies once servers share a network.",
      "Applies once servers share a network.",
    ]);
  });
});

describe("Fleet", () => {
  it("draws a quarantined server's card in its own words", () => {
    expect(
      fleetQuarantine(
        { quarantine: { at: "2026-10-27T14:18:01Z", why: "why" } },
        NOW,
      ),
    ).toEqual({
      chip: "Quarantined · 21:18",
      attention: "Quarantined · release it from the server",
      meters: "Reported by the Server Itself",
      footer: "Checks Not Trusted",
    });
    expect(fleetQuarantine({ quarantine: null }, NOW)).toBeNull();
  });
});

describe("History", () => {
  const action = (
    kind: ActionRecord["kind"],
    name: string,
    verb: ActionRecord["action"],
  ) =>
    ({
      kind,
      name,
      action: verb,
      status: "done",
      requestedBy: "Quarantine",
    }) as ActionRecord;

  it("words each action quarantine and Release queue", () => {
    expect(historyText(action("network", "kry0", "drop"))).toBe(
      "Drop a quarantined server",
    );
    expect(historyText(action("network", "kry0", "tighten"))).toBe(
      "Count scans more strictly",
    );
    expect(historyText(action("host", "tailscale", "block"))).toBe(
      "Block a quarantined server on Tailscale",
    );
    expect(historyText(action("host", "tailscale", "unblock"))).toBe(
      "Stop blocking a released server on Tailscale",
    );
    expect(historyText(action("host", "server", "accept"))).toBe(
      "Accept a change as yours",
    );
    expect(historyText(action("host", "server", "release"))).toBe(
      "Release the server with new keys",
    );
    expect(historyText(action("vault", "cloudflare", "release"))).toBe(
      "Share the Cloudflare token",
    );
  });
});

describe("the release batch", () => {
  const pending = {
    key: "bmV3LWtleQ",
    signer: "bmV3LXNpZ25lcg",
    seal: "bmV3LXNlYWw",
    token: "a".repeat(64),
    expires: "2026-10-27T14:20:00.000Z",
  };

  it("seals the released server's pairs to its new seal key, not the one it last reported", () => {
    expect(
      releaseInputs(record(), pending, V1, {
        locked: false,
        sealKeys: { [V1]: "b2xkLXNlYWw", [V2]: "c2VhbC0y" },
      }).sealKeys,
    ).toEqual({ [V1]: "bmV3LXNlYWw", [V2]: "c2VhbC0y" });
  });

  it("unlocks when the quarantine's own Lock Down ran, whatever the server reports", () => {
    expect(
      releaseInputs(record(), pending, V1, {
        locked: false,
        sealKeys: {},
      }).unlock,
    ).toBe(true);
    const failed = record({
      steps: [
        {
          nodeId: V1,
          nodeName: "vps-1",
          action: "lockdown",
          status: "failed",
          finishedAt: null,
        },
      ],
    });
    expect(
      releaseInputs(failed, pending, V1, {
        locked: false,
        sealKeys: {},
      }).unlock,
    ).toBe(false);
    expect(
      releaseInputs(failed, pending, V1, {
        locked: true,
        sealKeys: {},
      }).unlock,
    ).toBe(true);
  });

  it("sends the server's own steps and no block to lift", () => {
    expect(
      Object.keys(
        releaseInputs(record(), pending, V1, { locked: false, sealKeys: {} }),
      ).sort(),
    ).toEqual(["sealKeys", "unlock"]);
  });
});

describe("Change These while a reshare runs", () => {
  const step = (
    verb: ActionRecord["action"],
    status: ActionRecord["status"],
    kind: ActionRecord["kind"] = "vault",
  ) => ({ kind, name: "cloudflare", action: verb, status }) as ActionRecord;

  it("holds the token and web address rows until the reshare is done", () => {
    expect(resharing([step("reshare", "queued")])).toBe(true);
    expect(resharing([step("store", "sent")])).toBe(true);
    expect(resharing([step("release", "queued")])).toBe(true);
    expect(resharing([step("reshare", "done"), step("store", "failed")])).toBe(
      false,
    );
    expect(resharing([step("restart", "queued", "systemd")])).toBe(false);
    expect(resharing([])).toBe(false);
  });
});

describe("a reshare without the quarantined server", () => {
  it("says why it cannot run when the suspect held one of only two pieces", () => {
    const node = (id: string, name: string): VaultNode => ({
      id,
      name,
      sealKey: `seal-${name}`,
      vault: { set: "t1", holders: 2 },
      reachable: true,
      online: true,
    });
    expect(
      planWithout([node(V1, "vps-1"), node(V2, "vps-2")], V1, "t1"),
    ).toEqual({
      ok: false,
      reason:
        "Two servers other than vps-1 holding a piece must be online; 1 is.",
    });
  });
});

describe("temporary UDP ports", () => {
  it("reads a port range as the temporary ports one process uses", () => {
    const { title, detail } = warningStrip(
      warning("port", { port: "32768-60999/udp", process: "tailscaled" }),
      "vps-1",
      NOW,
    );
    expect([title, detail]).toEqual([
      "Temporary UDP ports 32768-60999 on a public address, not through Krynodes · 21:04",
      "Process tailscaled",
    ]);
  });
});
