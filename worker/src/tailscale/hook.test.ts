import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { app } from "../app";
import type { Env } from "../env";
import { hubHarness } from "../test/hub";
import { OWNER, seedNode } from "../test/seed";
import { createTestDb } from "../test/sqlite-d1";
import { policyChange } from "./hook";

const NOW = Date.parse("2026-10-27T03:12:00Z");
const MINUTE = 60_000;
const A = "11111111-1111-4111-8111-111111111111";
const C = "33333333-3333-4333-8333-333333333333";
const TAILNET = "tail0000.ts.net";
const CLIENT = "kQ1clientCNTRL";
const SECRET = "tskey-webhook-s3cret";
const iso = (ms: number) => new Date(ms).toISOString();

const BLOCK = (lines: string[]) =>
  [
    "{",
    "  // mine",
    '  "grants": [',
    "    // krynodes: begin · kept by Krynodes, change it there",
    ...lines.map((line) => `    ${line},`),
    "    // krynodes: end",
    "  ],",
    "}",
  ].join("\n");
const SSH = '{"src":["autogroup:member"],"dst":["tag:kry"],"ip":["tcp:22"]}';
const WEB = '{"src":["autogroup:member"],"dst":["tag:kry"],"ip":["tcp:80"]}';

const created = (node: string, managedBy: unknown, at = NOW) => ({
  timestamp: iso(at),
  version: 1,
  type: "nodeCreated",
  tailnet: TAILNET,
  message: `Node ${node}.${TAILNET} created`,
  data: {
    nodeID: node,
    deviceName: `${node}.${TAILNET}`,
    managedBy,
    actor: "owner@example.test",
    url: "https://login.tailscale.com/admin/machines/100.64.0.9",
  },
});

const updated = (actor: string, at = NOW) => ({
  timestamp: iso(at),
  version: 1,
  type: "policyUpdate",
  tailnet: TAILNET,
  message: "Tailnet policy file updated",
  data: {
    oldPolicy: BLOCK([SSH]),
    newPolicy: BLOCK([SSH, WEB]),
    actor,
    url: "https://login.tailscale.com/admin/acls",
  },
});

async function signature(secret: string, t: number, body: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${t}.${body}`),
  );
  return Buffer.from(mac).toString("hex");
}

function hooked() {
  const { db, sqlite } = createTestDb();
  for (const id of [A, C]) seedNode(sqlite, { id });
  sqlite
    .prepare(
      `INSERT INTO tailscale (owner_user_id, tailnet, client_id, webhook_secret, connected_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .run(OWNER, TAILNET, CLIENT, SECRET, iso(NOW - 60 * MINUTE));
  const mail: { subject: string; text: string; html: string }[] = [];
  const env = {
    DB: db,
    PUBLIC_ORIGIN: "https://kry.example.test",
    ALERT_EMAIL: "owner@example.test",
    FROM_EMAIL: "kry@example.test",
    EMAIL: {
      send: async (message: {
        subject: string;
        text: string;
        html: string;
      }) => {
        mail.push(message);
      },
    },
  } as unknown as Env;
  const harness = hubHarness(env);
  Object.assign(env, {
    FLEET: {
      idFromName: (name: string) => name,
      get: () => ({
        fetch: (url: string, init?: RequestInit) =>
          harness.hub.fetch(new Request(url, init)),
      }),
    },
  });
  const storage = (
    harness.hub as unknown as { ctx: { storage: { alarm: number | null } } }
  ).ctx.storage;
  const post = async (
    events: unknown[],
    options: { secret?: string; age?: number; header?: string } = {},
  ) => {
    const body = JSON.stringify(events);
    const t = Math.floor((Date.now() - (options.age ?? 0) * 1000) / 1000);
    const v1 = await signature(options.secret ?? SECRET, t, body);
    return app.request(
      `https://kry.kleavox.workers.dev/hooks/tailscale`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "tailscale-webhook-signature": options.header ?? `t=${t},v1=${v1}`,
        },
        body,
      },
      env,
    );
  };
  const alarms = () =>
    sqlite
      .prepare(
        "SELECT kind, device, detail, at, due_at, raised_at FROM tailscale_alarms ORDER BY at, device",
      )
      .all() as {
      kind: string;
      device: string | null;
      detail: string;
      at: string;
      due_at: string | null;
      raised_at: string | null;
    }[];
  const action = (
    node: string,
    kind: string,
    name: string,
    verb: string,
    status: string,
    finishedAt: string | null = null,
    id = crypto.randomUUID(),
  ) =>
    sqlite
      .prepare(
        `INSERT INTO actions (id, batch_id, position, mode, node_id, kind, name, action, status,
           requested_by, requested_at, finished_at)
         VALUES (?, ?, 0, 'parallel', ?, ?, ?, ?, ?, 'owner', ?, ?)`,
      )
      .run(id, id, node, kind, name, verb, status, iso(Date.now()), finishedAt);
  const wake = async (at: number) => {
    vi.setSystemTime(at);
    await harness.hub.alarm();
  };
  return { sqlite, mail, storage, post, alarms, action, wake, harness };
}

describe("the Tailscale webhook", () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: NOW, toFake: ["Date"] });
  });
  afterEach(() => vi.useRealTimers());

  it("accepts a signature 299 seconds old and refuses one 301 seconds old", async () => {
    const t = hooked();
    const event = [created("nas-7", "tag:kry")];
    expect((await t.post(event, { age: 299 })).status).toBe(200);
    expect(t.alarms()).toHaveLength(1);
    t.sqlite.prepare("DELETE FROM tailscale_alarms").run();
    expect((await t.post(event, { age: 301 })).status).toBe(401);
    expect(t.alarms()).toEqual([]);
  });

  it("refuses another secret, a tailnet nobody connected, a replay and a bad header, storing and mailing nothing", async () => {
    const t = hooked();
    const event = created("nas-7", "tag:kry");
    expect((await t.post([event], { secret: "tskey-other" })).status).toBe(401);
    expect((await t.post([{ ...event, tailnet: "other.ts.net" }])).status).toBe(
      401,
    );
    expect((await t.post([event], { age: 600 })).status).toBe(401);
    expect((await t.post([event], { header: "t=1,v1=zz" })).status).toBe(401);
    expect((await t.post([event], { header: "" })).status).toBe(401);
    expect(t.alarms()).toEqual([]);
    await t.wake(NOW + 20 * MINUTE);
    expect(t.mail).toEqual([]);
  });

  it("stores each of three events in one body and wakes the hub at the earliest", async () => {
    const t = hooked();
    const response = await t.post([
      created("nas-7", "tag:kry", NOW - 2 * MINUTE),
      created("nas-8", ["tag:nas", "tag:kry"], NOW - MINUTE),
      created("nas-9", "tag:kry"),
    ]);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});
    expect(t.alarms().map((alarm) => [alarm.device, alarm.due_at])).toEqual([
      ["nas-7", iso(NOW + MINUTE)],
      ["nas-8", iso(NOW + 2 * MINUTE)],
      ["nas-9", iso(NOW + 3 * MINUTE)],
    ]);
    expect(t.storage.alarm).toBe(NOW + MINUTE);
  });

  it("stores nothing for a node created without the tag", async () => {
    const t = hooked();
    expect(
      (await t.post([created("laptop", "owner@example.test")])).status,
    ).toBe(200);
    expect(
      (
        await t.post([
          {
            timestamp: iso(NOW),
            version: 1,
            type: "test",
            tailnet: TAILNET,
            message: "This is a test event",
            data: null,
          },
        ])
      ).status,
    ).toBe(200);
    expect(t.alarms()).toEqual([]);
    expect(t.storage.alarm).toBeNull();
  });

  it("raises a tagged node Krynodes never signed in after three minutes and mails once", async () => {
    const t = hooked();
    await t.post([created("nas-7", "tag:kry")]);
    await t.post([created("nas-7", "tag:kry")]);
    expect(t.alarms()).toHaveLength(1);
    await t.wake(NOW + 2 * MINUTE);
    expect(t.alarms()[0]!.raised_at).toBeNull();
    await t.wake(NOW + 3 * MINUTE);
    expect(t.alarms()[0]).toMatchObject({
      kind: "device",
      device: "nas-7",
      raised_at: iso(NOW + 3 * MINUTE),
      due_at: null,
    });
    expect(JSON.parse(t.alarms()[0]!.detail)).toEqual({
      name: "nas-7.tail0000.ts.net",
      tag: "tag:kry",
    });
    await t.wake(NOW + 10 * MINUTE);
    expect(t.mail.map((message) => message.subject)).toEqual([
      "[Krynodes] nas-7 joined your tailnet with your servers' tag",
    ]);
    const text = t.mail[0]!.text;
    expect(text).toContain(
      "Krynodes did not sign it in. Your rules give it nothing, but someone may have your Tailscale credential.",
    );
    expect(text).toContain("Device: nas-7.tail0000.ts.net");
    expect(text).toContain("Tag: tag:kry");
    expect(text).toContain("Joined: 2026-10-27 03:12 UTC");
    expect(text).toContain("Open Network: https://kry.example.test/network");
    expect(text).toContain(
      "If you signed it in yourself, enroll it in Krynodes. If not, remove it and delete Krynodes' credential in Tailscale's admin console, then connect a new one.",
    );
    expect(t.mail[0]!.html).toContain("Tailscale");
  });

  it("waits while a join is still running, drops the node once Krynodes signs it in, and never waits past fifteen minutes", async () => {
    const t = hooked();
    t.action(C, "host", "tailscale", "join", "sent");
    await t.post([created("nJoin", "tag:kry")]);
    await t.wake(NOW + 3 * MINUTE);
    expect(t.alarms()[0]).toMatchObject({
      due_at: iso(NOW + 6 * MINUTE),
      raised_at: null,
    });
    expect(t.storage.alarm).toBe(NOW + 6 * MINUTE);
    t.sqlite
      .prepare(
        "INSERT INTO tailscale_nodes (node_id, device, joined_at) VALUES (?, ?, ?)",
      )
      .run(C, "nJoinCNTRL", iso(NOW + 4 * MINUTE));
    await t.wake(NOW + 6 * MINUTE);
    expect(t.alarms()).toEqual([]);

    await t.post([created("nStuck", "tag:kry", NOW + 6 * MINUTE)]);
    for (const minutes of [9, 12, 15, 18]) {
      await t.wake(NOW + minutes * MINUTE);
      expect(t.alarms()[0]!.raised_at).toBeNull();
    }
    await t.wake(NOW + 20 * MINUTE);
    expect(t.alarms()[0]!.raised_at).toBeNull();
    await t.wake(NOW + 21 * MINUTE);
    expect(t.alarms()[0]!.raised_at).toBe(iso(NOW + 21 * MINUTE));
    expect(t.mail).toHaveLength(1);
  });

  it("stores nothing for a node Krynodes already signed in", async () => {
    const t = hooked();
    t.sqlite
      .prepare(
        "INSERT INTO tailscale_nodes (node_id, device, joined_at) VALUES (?, ?, ?)",
      )
      .run(C, "nDoneCNTRL", iso(NOW));
    expect((await t.post([created("nDoneCNTRL", "tag:kry")])).status).toBe(200);
    expect((await t.post([created("nDone", "tag:kry")])).status).toBe(200);
    expect(t.alarms()).toEqual([]);
  });

  it("stores nothing for a policy change made by the owner", async () => {
    const t = hooked();
    expect((await t.post([updated("owner@example.test")])).status).toBe(200);
    expect(t.alarms()).toEqual([]);
    await t.wake(NOW + 5 * MINUTE);
    expect(t.mail).toEqual([]);
  });

  it("ignores Krynodes' credential during a save, raises it three minutes after and mails once", async () => {
    const t = hooked();
    t.action(A, "vault", "tailscale", "save", "sent");
    await t.post([updated(CLIENT)]);
    expect(t.alarms()).toEqual([]);
    t.sqlite
      .prepare("UPDATE actions SET status = 'done', finished_at = ?")
      .run(iso(NOW + 10_000));
    vi.setSystemTime(NOW + MINUTE);
    await t.post([updated(CLIENT, NOW + MINUTE)]);
    expect(t.alarms()).toEqual([]);

    const later = NOW + 10_000 + 3 * MINUTE;
    vi.setSystemTime(later);
    await t.post([updated(CLIENT, later)]);
    await t.post([updated(CLIENT, later)]);
    expect(t.alarms()).toHaveLength(1);
    expect(t.storage.alarm).toBe(later + 1_000);
    await t.wake(later + 1_000);
    await t.wake(later + 5 * MINUTE);
    expect(t.alarms()[0]).toMatchObject({
      kind: "policy",
      raised_at: iso(later + 1_000),
    });
    expect(JSON.parse(t.alarms()[0]!.detail)).toEqual({
      block: true,
      added: 1,
      removed: 0,
      lines: [`+ ${WEB}`],
    });
    expect(t.mail.map((message) => message.subject)).toEqual([
      "[Krynodes] Your Tailscale policy was changed without your passkey",
    ]);
    const text = t.mail[0]!.text;
    expect(text).toContain(
      "The change was made with Krynodes' credential, and you signed no change in Krynodes. Someone else has the credential.",
    );
    expect(text).toContain("Changed: 2026-10-27 03:15 UTC");
    expect(text).toContain("Change: 1 rule added, shown on the Network page");
    expect(text).toContain("Open Network: https://kry.example.test/network");
    expect(text).toContain(
      "Delete Krynodes' credential in Tailscale's admin console, put the policy back there, then connect a new credential.",
    );
  });

  it("puts no client ID or secret in any mail", async () => {
    const t = hooked();
    await t.post([created("nas-7", "tag:kry"), updated(CLIENT)]);
    await t.wake(NOW + 1_000);
    await t.wake(NOW + 3 * MINUTE);
    expect(t.mail).toHaveLength(2);
    for (const message of t.mail) {
      for (const secret of [CLIENT, SECRET]) {
        expect(message.text).not.toContain(secret);
        expect(message.html).not.toContain(secret);
      }
    }
  });
});

describe("policyChange", () => {
  it("compares Krynodes' block when both sides have it, the whole text otherwise, at most 20 lines of 200", () => {
    expect(policyChange(BLOCK([SSH, WEB]), BLOCK([WEB]))).toEqual({
      block: true,
      added: 0,
      removed: 1,
      lines: [`- ${SSH}`],
    });
    expect(
      policyChange('{\n  "acls": [],\n}', '{\n  "acls": [],\n  "ssh": [],\n}'),
    ).toEqual({ block: false, added: 1, removed: 0, lines: ['+ "ssh": []'] });
    expect(
      policyChange(BLOCK([SSH]), BLOCK([SSH]).replace("// mine", '"ssh": [],')),
    ).toEqual({
      block: false,
      added: 1,
      removed: 1,
      lines: ["- // mine", '+ "ssh": []'],
    });
    const many = Array.from(
      { length: 30 },
      (_, index) => `"x${index}": "${"y".repeat(300)}"`,
    );
    const wide = policyChange("{\n}", ["{", ...many, "}"].join("\n"));
    expect(wide.added).toBe(30);
    expect(wide.lines).toHaveLength(20);
    expect(wide.lines.every((line) => line.length <= 200)).toBe(true);
  });
});

describe("the hub's Tailscale alarm", () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: NOW, toFake: ["Date"] });
  });
  afterEach(() => vi.useRealTimers());

  it("is set for the earliest due row", async () => {
    const { hub } = hubHarness({});
    const storage = (
      hub as unknown as { ctx: { storage: { alarm: number | null } } }
    ).ctx.storage;
    const due = (at: number) =>
      hub.fetch(
        new Request("https://fleet/tailnet", {
          method: "POST",
          body: JSON.stringify({ owner: OWNER, due: at }),
        }),
      );
    await due(NOW + 5 * MINUTE);
    expect(storage.alarm).toBe(NOW + 5 * MINUTE);
    await due(NOW + 3 * MINUTE);
    expect(storage.alarm).toBe(NOW + 3 * MINUTE);
    await due(NOW + 10 * MINUTE);
    expect(storage.alarm).toBe(NOW + 3 * MINUTE);
  });
});
