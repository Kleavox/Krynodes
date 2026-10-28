import { describe, expect, it, vi } from "vitest";

import type { Env } from "../env";
import {
  sendQuarantineEmail,
  sendServerEmail,
  sendStoppedEmail,
  sendTokenEmail,
  sendWarningEmail,
} from "./mail";

function mailEnv(extra: Partial<Env> = {}) {
  const send = vi.fn(async () => ({ messageId: "m-1" }));
  const env = {
    EMAIL: { send },
    ALERT_EMAIL: "operator@example.test",
    FROM_EMAIL: "kry@example.test",
    PUBLIC_ORIGIN: "https://kry.example.test",
    ...extra,
  } as unknown as Env;
  const sent = () =>
    (send.mock.calls[0] as unknown as [Record<string, string>])[0];
  return { env, send, sent };
}

const at = "2026-09-28T08:05:09.123Z";
const down = (checkName: string | null, summary = `${checkName} is down`) => ({
  checkName,
  summary,
  occurredAt: at,
});

describe("incident email", () => {
  it("goes to the operator through the Cloudflare binding, one mail per server", async () => {
    const { env, sent } = mailEnv();
    await sendServerEmail(env, {
      nodeId: "n1",
      nodeName: "pivox",
      down: [
        down("API <health>", "API <health> is down: timeout"),
        down("Web"),
      ],
    });
    const message = sent();
    expect(message.to).toBe("operator@example.test");
    expect(message.from).toEqual({
      name: "Krynodes",
      email: "kry@example.test",
    });
    expect(message.subject).toBe(
      "[Krynodes] pivox: 2 checks down — API <health>, Web",
    );
    expect(message.html).toContain("API &lt;health&gt;");
    expect(message.html).not.toContain("<health>");
    expect(message.html).toContain("2026-09-28 08:05 UTC");
    expect(message.html).toContain(
      'href="https://kry.example.test/checks?status=down"',
    );
    expect(message.html).toContain("Open Checks");
    expect(message.html).not.toMatch(/Pulse|Kleavox/u);
    expect(message.text).toContain("timeout");
    expect(message.text).toContain(
      "https://kry.example.test/checks?status=down",
    );
  });

  it("says plainly when a server stops reporting", async () => {
    const { env, sent } = mailEnv();
    await sendServerEmail(env, {
      nodeId: "n1",
      nodeName: "pivox",
      down: [down(null, "pivox stopped reporting")],
    });
    expect(sent().subject).toBe("[Krynodes] pivox: offline");
    expect(sent().text).toContain("Last report: 2026-09-28 08:05 UTC");
    expect(sent().text).toContain("https://kry.example.test/nodes/n1");
  });

  it("writes row labels as they are, without uppercase", async () => {
    const { env, sent } = mailEnv();
    await sendTokenEmail(env, { expiresAt: "2026-11-20T00:00:00.000Z" });
    expect(sent().html).toContain(">Expires</td>");
    expect(sent().html).not.toContain("text-transform:uppercase");
    expect(sent().html).not.toContain("letter-spacing:0.06em");
  });

  it("sends no stopped-stack mail when no operator address or binding is configured", async () => {
    for (const extra of [{ ALERT_EMAIL: undefined }, { EMAIL: undefined }]) {
      const { env, send } = mailEnv(extra);
      await sendStoppedEmail(env, {
        nodeId: "n1",
        nodeName: "vps-1",
        project: "app",
        count: 4,
        tried: [],
        at,
      });
      expect(send).not.toHaveBeenCalled();
    }
  });

  it("sends nothing when no operator address or binding is configured", async () => {
    for (const extra of [{ ALERT_EMAIL: undefined }, { EMAIL: undefined }]) {
      const { env, send } = mailEnv(extra);
      await sendServerEmail(env, {
        nodeId: "n1",
        nodeName: "pivox",
        down: [down("API")],
      });
      expect(send).not.toHaveBeenCalled();
    }
  });
});

const buttons = (html: string | undefined) =>
  html?.match(/<a href=/gu)?.length ?? 0;

describe("quarantine mail", () => {
  const warned = {
    nodeId: "n1",
    nodeName: "vps-1",
    at: "2026-10-27T21:04:10.000Z",
    cutAt: Date.parse("2026-10-27T21:19:10.000Z"),
  };

  it("warns of a new SSH key with the minute it is cut off, and only tells", async () => {
    const { env, sent } = mailEnv();
    await sendWarningEmail(env, {
      ...warned,
      kind: "ssh-key",
      detail: {
        user: "root",
        file: "/root/.ssh/authorized_keys",
        key: "ED25519 SHA256:abc laptop",
      },
    });
    const { subject, text, html } = sent();
    expect(subject).toBe("[Krynodes] vps-1: new SSH key for root");
    for (const line of [
      "A key was added to /root/.ssh/authorized_keys and not through Krynodes. If you did not add it, do nothing: vps-1 is cut off from the private network at 21:19 UTC.",
      "Server: vps-1",
      "Key: ED25519 SHA256:abc laptop",
      "Added: 2026-10-27 21:04 UTC",
      "Cut off: 2026-10-27 21:19 UTC, unless you say it was you",
      "Open vps-1: https://kry.example.test/nodes/n1",
      "It Was Me is on the server page and asks for your passkey. Nothing in this mail can answer for you.",
    ]) {
      expect(text).toContain(line);
    }
    expect(html).toContain("#f5b544");
    expect(html).toContain("Warning</span>");
    expect(buttons(html)).toBe(1);
    expect(html).not.toContain("uppercase");
  });

  it("gives every other warning its own heading and rows, and no cut-off under Warn Only", async () => {
    const cases: [string, Record<string, string>, string, string[]][] = [
      [
        "ssh-login",
        {
          user: "root",
          from: "203.0.113.9",
          key: "ED25519 SHA256:x",
          at: "2026-10-27T21:03:00Z",
        },
        "vps-1: root signed in with a key not from Krynodes",
        ["From: 203.0.113.9", "At: 2026-10-27 21:03 UTC"],
      ],
      [
        "user",
        { user: "eve" },
        "vps-1: new user eve",
        ["User: eve", "Added: 2026-10-27 21:04 UTC"],
      ],
      [
        "sudo",
        { rule: "/etc/sudoers.d/eve" },
        "vps-1: new sudo rule",
        ["Rule: /etc/sudoers.d/eve"],
      ],
      [
        "rule",
        { chain: "KRY-REACH", rule: "-A KRY-REACH -j DROP" },
        "vps-1: Krynodes' firewall rule was removed",
        ["Rule: KRY-REACH · -A KRY-REACH -j DROP"],
      ],
      [
        "port",
        { port: "0.0.0.0:4444/tcp", process: "nc" },
        "vps-1: a port was opened outside Krynodes",
        ["Port: 0.0.0.0:4444/tcp", "Process: nc"],
      ],
      [
        "port",
        { port: "32768-60999/udp", process: "tailscaled" },
        "vps-1: temporary UDP ports were opened outside Krynodes",
        [
          "tailscaled uses temporary UDP ports (32768-60999/udp) on a public address and not through Krynodes. If you did not start it",
          "Port: 32768-60999/udp",
          "Process: tailscaled",
        ],
      ],
      [
        "quiet",
        { lastReport: "2026-10-27T20:58:00.000Z", seenBy: "vps-2, vps-3" },
        "vps-1: the agent went quiet while the server is up",
        ["Last report: 2026-10-27 20:58 UTC", "Seen by: vps-2, vps-3"],
      ],
    ];
    for (const [kind, detail, heading, rows] of cases) {
      const { env, sent } = mailEnv();
      await sendWarningEmail(env, { ...warned, kind, detail, cutAt: null });
      expect(sent().subject).toBe(`[Krynodes] ${heading}`);
      for (const row of rows) expect(sent().text).toContain(row);
      expect(sent().text).not.toContain("Cut off:");
      expect(sent().text).toContain("cut vps-1 off from the server page");
    }
  });

  it("tells of a quarantine in counts, never by name, and how to release it", async () => {
    const { env, sent } = mailEnv();
    await sendQuarantineEmail(env, {
      nodeId: "n1",
      nodeName: "vps-1",
      why: "vps-2 and vps-3 saw it knock on 41 closed ports in one minute",
      at: "2026-10-27T21:18:04.000Z",
      droppedBy: ["vps-2", "vps-3"],
      stacks: 2,
      pieces: 1,
      trusted: 1,
      tailnet: true,
    });
    const { subject, text, html } = sent();
    expect(subject).toBe("[Krynodes] vps-1 is quarantined");
    for (const line of [
      "vps-2 and vps-3 saw it knock on 41 closed ports in one minute. The other servers dropped it, and Krynodes refuses every action there except reading.",
      "Server: vps-1",
      "Why: vps-2 and vps-3 saw it knock on 41 closed ports in one minute",
      "Cut off: 2026-10-27 21:18 UTC",
      "Dropped by: vps-2 and vps-3",
      "Change: The secrets of 2 stacks, 1 Cloudflare token piece and 1 service that trusted it, and its place on your tailnet, listed on the server page",
      "Reinstall vps-1 if it was broken into. If it was a false alarm, release it from the server itself: run sudo kry release-code there, then type its code with your passkey.",
    ]) {
      expect(text).toContain(line);
    }
    expect(html).toContain("Quarantined</span>");
    expect(html).toContain("#f0616d");
    expect(buttons(html)).toBe(1);
  });

  it("says what a quarantine could reach when it reached nothing known", async () => {
    const { env, sent } = mailEnv();
    await sendQuarantineEmail(env, {
      nodeId: "n1",
      nodeName: "vps-1",
      why: "Reported from two machines at once",
      at: "2026-10-27T21:18:04.000Z",
      droppedBy: [],
      stacks: 0,
      pieces: 0,
      trusted: 0,
      tailnet: false,
    });
    expect(sent().text).toContain("Dropped by: --");
    expect(sent().text).toContain(
      "Change: Nothing Krynodes knows of; see the server page",
    );
  });

  it("tells of a stopped stack with four places and the rest counted", async () => {
    const { env, sent } = mailEnv();
    await sendStoppedEmail(env, {
      nodeId: "n1",
      nodeName: "vps-1",
      project: "app",
      count: 14,
      tried: [
        "10.88.0.2:22/tcp",
        "10.88.0.2:80/tcp",
        "10.88.0.3:22/tcp",
        "10.88.0.3:5432/tcp",
      ],
      at: "2026-10-27T21:04:00.000Z",
    });
    const { subject, text, html } = sent();
    expect(subject).toBe("[Krynodes] app on vps-1 was stopped");
    for (const line of [
      "A container in app tried 14 places it was not given. Krynodes stopped the stack, and it stays stopped after a reboot. vps-1 is still trusted.",
      "Stack: app",
      "Tried: 10.88.0.2:22/tcp, 10.88.0.2:80/tcp, 10.88.0.3:22/tcp, 10.88.0.3:5432/tcp and 10 more",
      "Stopped: 2026-10-27 21:04 UTC",
      "Change: The secrets of app, listed on the server page",
      "Change its secrets before you start it again. Start asks for your passkey.",
    ]) {
      expect(text).toContain(line);
    }
    expect(html).toContain("Stopped</span>");
    expect(buttons(html)).toBe(1);
  });
});
